//go:build android

package certmanager

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/SnishaperTeam/snishaper-core/config"
)

// Android trust store. conscrypt's TrustedCertificateStore scans the whole CA
// directory and indexes certificates by subject, so the file name does not take
// part in trust decisions — it only has to be unique and recognisably ours.
// Anchors are named "<brand>-ca-<thumbprint8>.0"; the brand prefix keeps one
// embedder from listing or removing another's root.
//
// Root access goes through su (Magisk / KernelSU / APatch / vendor su). The
// install script (see cert_android_script.go) overlays
// /system/etc/security/cacerts with a tmpfs in the global mount namespace,
// which works even on read-only /system partitions, and rebinds the private
// conscrypt APEX view of every mount namespace onto it (Android 14+). The
// overlay does not survive a reboot, so the UI tells the user to reinstall
// after rebooting.

// suPath caches the first su binary that launched successfully.
var suPath struct {
	sync.Mutex
	bin string
}

// suScript runs script as root through the su binary. The timeout bounds a
// pending Magisk grant dialog so a never-answered prompt cannot hang callers.
// $PATH lookup misses some root solutions (KernelSU and APatch do not inject
// su into the app environment), so on a launch failure the absolute
// candidates in androidSuCandidates are walked and the first working one is
// cached.
func suScript(timeout time.Duration, script string) (string, error) {
	// The su shell must never depend on the app process' PATH (see
	// androidShellPathPrefix).
	script = androidShellPathPrefix + "\n" + script

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	run := func(bin string) (string, error) {
		out, err := exec.CommandContext(ctx, bin, "-c", script).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}

	suPath.Lock()
	bin := suPath.bin
	suPath.Unlock()
	if bin == "" {
		bin = androidSuCandidates[0]
	}

	combined, err := run(bin)
	if err != nil && bin == androidSuCandidates[0] && isSuLaunchFailure(err) {
		for _, cand := range androidSuCandidates[1:] {
			combined, err = run(cand)
			if err == nil || !isSuLaunchFailure(err) {
				suPath.Lock()
				if suPath.bin == "" {
					suPath.bin = cand
				}
				suPath.Unlock()
				break
			}
		}
	}
	if err != nil {
		msg := combined
		if msg == "" {
			msg = err.Error()
		}
		return combined, fmt.Errorf("su: %s", msg)
	}
	return combined, nil
}

// isSuLaunchFailure reports whether err means the su binary itself could not
// be executed (missing from $PATH, absent, or not executable), as opposed to
// the script running and failing.
func isSuLaunchFailure(err error) bool {
	return errors.Is(err, exec.ErrNotFound) ||
		errors.Is(err, fs.ErrNotExist) ||
		errors.Is(err, fs.ErrPermission)
}

// androidRequireRoot verifies that su exists and grants uid 0.
func androidRequireRoot() error {
	out, err := suScript(45*time.Second, "id")
	if err != nil {
		return fmt.Errorf("无法获取 root 权限（su 执行失败）：%w", err)
	}
	if !strings.Contains(out, "uid=0") {
		return errors.New("su 未授予 root 权限（uid 非 0），请在 Magisk / 超级用户中允许本应用")
	}
	return nil
}

func platformInstallHelp(brand config.Brand) string {
	return "需要已 root 的设备（Magisk / KernelSU 等）：安装会通过 su 把 CA 注入系统信任库（tmpfs 覆盖 + 逐应用命名空间 bind）；" +
		"注入不持久，重启后需重新安装；安装后已运行的应用立即识别新证书，无需重启"
}

// androidReadCACertPEM reads one trust-store file through su, trying each
// directory in turn: the global (init) namespace view first, then the local
// one. Directories may be empty or duplicated; they are skipped.
func androidReadCACertPEM(dirs []string, name string) ([]byte, error) {
	attempts := make([]string, 0, len(dirs))
	seen := make(map[string]bool, len(dirs))
	for _, dir := range dirs {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		file := dir + "/" + name
		attempts = append(attempts,
			"nsenter -t 1 -m -- cat "+shQuote(file)+" 2>/dev/null || cat "+shQuote(file)+" 2>/dev/null")
	}
	if len(attempts) == 0 {
		return nil, fmt.Errorf("%s: 未找到", name)
	}
	// Trailing true: a failed attempt must not fail the whole script when an
	// earlier one already produced the certificate.
	script := strings.Join(attempts, "\n") + "\ntrue"
	out, err := suScript(30*time.Second, script)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("%s: 未找到", name)
	}
	return []byte(out), nil
}

// parseAndroidCertPEM decodes the first CERTIFICATE PEM block.
func parseAndroidCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func platformCACertInstalled(brand config.Brand, thumbprint string) bool {
	data, err := androidReadCACertPEM([]string{androidLegacyCertDir}, androidCACertName(brand, thumbprint))
	if err != nil {
		return false
	}
	cert, err := parseAndroidCertPEM(data)
	if err != nil {
		return false
	}
	return strings.EqualFold(certThumbprint(cert), thumbprint)
}

func platformListCerts(brand config.Brand) ([]InstalledCert, error) {
	if err := androidRequireRoot(); err != nil {
		return nil, err
	}
	pattern := strings.TrimSuffix(caAnchorFileNameFor(brand), ".crt") + "-*.0"
	sys := androidLegacyCertDir
	stage := androidStageDir(brand)
	// The glob must expand inside the (possibly global-namespace) shell, so the
	// ls runs in an inner sh -c with the pattern left unquoted. The stage
	// directory is listed too, so v0.8.7 leftovers can still be uninstalled.
	script := `nsenter -t 1 -m -- sh -c "ls ` + sys + `/` + pattern + `" 2>/dev/null` +
		`; sh -c "ls ` + sys + `/` + pattern + `" 2>/dev/null` +
		`; sh -c "ls ` + stage + `/` + pattern + `" 2>/dev/null; true`
	out, err := suScript(30*time.Second, script)
	if err != nil || strings.TrimSpace(out) == "" {
		return []InstalledCert{}, nil
	}

	result := []InstalledCert{}
	seen := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if name == "" || strings.Contains(name, "No such file") || strings.ContainsAny(name, " *") {
			continue
		}
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		data, err := androidReadCACertPEM([]string{sys, stage}, name)
		if err != nil {
			continue
		}
		cert, err := parseAndroidCertPEM(data)
		if err != nil {
			continue
		}
		if !isOwnCert(brand, cert) {
			continue
		}
		result = append(result, InstalledCert{
			Subject:       cert.Subject.String(),
			Thumbprint:    certThumbprint(cert),
			NotAfter:      cert.NotAfter.Format("2006-01-02 15:04:05"),
			StoreName:     name,
			StoreLocation: sys,
			Token:         sys + "|" + name + "|" + certThumbprint(cert),
		})
	}
	return result, nil
}

func platformInstallCA(brand config.Brand, caPath string) error {
	if err := androidRequireRoot(); err != nil {
		return err
	}
	data, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	cert, err := parseAndroidCertPEM(data)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}
	thumbprint := certThumbprint(cert)
	name := androidCACertName(brand, thumbprint)

	// Generous timeout: the per-app namespace rebinding walks every running app.
	out, err := suScript(120*time.Second, androidInstallScript(brand, caPath, name))
	if err != nil {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	if !strings.Contains(out, androidInstallConfirm) {
		return fmt.Errorf("安装脚本未确认成功：%s", strings.TrimSpace(out))
	}
	// Confirm through the same read path the status check uses, so the UI badge
	// and the installed file can never disagree.
	if !platformCACertInstalled(brand, thumbprint) {
		return errors.New("安装脚本已执行，但未在系统信任库中检测到 CA；请确认 root 授权后重试")
	}
	return nil
}

func platformUninstallCert(brand config.Brand, storeLocation, storeName, thumbprint string) error {
	if err := androidRequireRoot(); err != nil {
		return err
	}
	name := storeName
	if name == "" {
		name = androidCACertName(brand, thumbprint)
	}

	// Trust boundary: only delete an anchor that really is this app's CA. The
	// name pattern alone is not proof — verify the thumbprint when the file
	// parses, and require the brand token in the subject.
	dirs := []string{storeLocation, androidLegacyCertDir, androidStageDir(brand)}
	if data, err := androidReadCACertPEM(dirs, name); err == nil {
		if cert, parseErr := parseAndroidCertPEM(data); parseErr == nil {
			if !isOwnCert(brand, cert) {
				return errors.New("拒绝卸载：该证书不属于本应用")
			}
			if thumbprint != "" && !strings.EqualFold(certThumbprint(cert), thumbprint) {
				return errors.New("拒绝卸载：信任库中的证书与请求的指纹不一致")
			}
		}
	}

	if _, err := suScript(60*time.Second, androidUninstallScript(brand, name)); err != nil {
		return fmt.Errorf("卸载失败：%w", err)
	}
	return nil
}

// isOwnCert reports whether cert was issued by this application's CA: its
// subject or issuer carries the product name. Matching is restricted to the
// brand (see config.Brand.OwnNames) so one application never lists — or
// uninstalls — another's root.
func isOwnCert(brand config.Brand, cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	subject := strings.ToLower(cert.Subject.String())
	issuer := strings.ToLower(cert.Issuer.String())
	for _, token := range brand.OwnNames() {
		if token == "" {
			continue
		}
		if strings.Contains(subject, token) || strings.Contains(issuer, token) {
			return true
		}
	}
	return false
}
