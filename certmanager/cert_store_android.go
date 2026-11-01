//go:build android

package certmanager

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/SnishaperTeam/snishaper-core/config"
)

// Android trust store. conscrypt's TrustedCertificateStore scans the whole CA
// directory and indexes certificates by subject, so the file name does not take
// part in trust decisions — it only has to be unique and recognisably ours.
// Anchors are named "<brand>-ca-<thumbprint8>.0"; the brand prefix keeps one
// embedder from listing or removing another's root.
//
// Root access goes through su (Magisk / KernelSU / vendor su). Two layouts:
//
//   - Android <= 13: write into /system/etc/security/cacerts behind a temporary
//     rw remount of /system.
//   - Android >= 14: apps read CAs from the conscrypt APEX. Copy its contents
//     to a staging directory, add the anchor, then mount --bind the staging
//     directory over /apex/com.android.conscrypt/cacerts. Bind mounts do not
//     survive a reboot, so the UI tells the user to reinstall after reboot.
//
// Mount operations must happen in the global mount namespace to affect other
// apps, hence the nsenter(1) into PID 1 with a plain fallback for single
// namespace systems (emulators).

const (
	androidLegacyCertDir  = "/system/etc/security/cacerts"        // Android <= 13
	androidConscryptDir   = "/apex/com.android.conscrypt/cacerts" // Android >= 14
	androidStageDirRoot   = "/data/local/tmp"
	androidBindMountSDK   = 34
	androidInstallConfirm = "SNISHAPER_CA_OK"
)

func platformInstallHelp(brand config.Brand) string {
	return "需要已 root 的设备（Magisk / KernelSU 等）：安装会通过 su 自动写入系统信任库；" +
		"Android 14+ 使用 bind mount 方案，重启后需重新安装，已运行的应用也需重启后才能识别新证书"
}

// androidCACertName builds the trust-store file name for one CA generation.
// The thumbprint prefix makes every regeneration a distinct file, so an
// InstallCA that drops the old generation cannot collide with itself.
func androidCACertName(brand config.Brand, thumbprint string) string {
	safe := strings.TrimSuffix(caAnchorFileNameFor(brand), ".crt")
	tp := strings.ToLower(strings.ReplaceAll(thumbprint, ":", ""))
	if len(tp) > 8 {
		tp = tp[:8]
	}
	return safe + "-" + tp + ".0"
}

// androidStageDir is the Android 14+ staging directory the bind mount serves.
func androidStageDir(brand config.Brand) string {
	safe := strings.TrimSuffix(caAnchorFileNameFor(brand), ".crt")
	return androidStageDirRoot + "/" + safe + "-cacerts"
}

// suScript runs script as root through the su binary. The timeout bounds a
// pending Magisk grant dialog so a never-answered prompt cannot hang callers.
func suScript(timeout time.Duration, script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "su", "-c", script).CombinedOutput()
	combined := strings.TrimSpace(string(out))
	if err != nil {
		msg := combined
		if msg == "" {
			msg = err.Error()
		}
		return combined, fmt.Errorf("su: %s", msg)
	}
	return combined, nil
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

// androidTrustDir returns the CA directory for the running Android version.
// Requires root; empty when the SDK cannot be determined.
func androidTrustDir() string {
	out, err := suScript(20*time.Second, "getprop ro.build.version.sdk")
	if err != nil {
		return ""
	}
	sdk := 0
	for _, field := range strings.Fields(out) {
		if v, convErr := strconv.Atoi(field); convErr == nil {
			sdk = v
		}
	}
	if sdk >= androidBindMountSDK {
		return androidConscryptDir
	}
	if sdk == 0 {
		return ""
	}
	return androidLegacyCertDir
}

// androidReadCACertPEM reads one trust-store file through su. Android 14+
// serves the bind-mounted directory only in the global mount namespace, so the
// global view (nsenter into PID 1) is tried first, then the local one.
func androidReadCACertPEM(dir, name string) ([]byte, error) {
	file := dir + "/" + name
	script := "nsenter -t 1 -m -- cat '" + file + "' 2>/dev/null || cat '" + file + "' 2>/dev/null"
	out, err := suScript(30*time.Second, script)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("%s: 未找到", file)
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

// shQuote single-quotes s for the su shell script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func platformCACertInstalled(brand config.Brand, thumbprint string) bool {
	dir := androidTrustDir()
	if dir == "" {
		return false
	}
	data, err := androidReadCACertPEM(dir, androidCACertName(brand, thumbprint))
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
	dir := androidTrustDir()
	if dir == "" {
		return nil, errors.New("无法确定 Android 版本（getprop 失败）")
	}
	pattern := strings.TrimSuffix(caAnchorFileNameFor(brand), ".crt") + "-*.0"
	// The glob must expand inside the (possibly global-namespace) shell, so the
	// ls runs in an inner sh -c with the pattern left unquoted.
	script := "nsenter -t 1 -m -- sh -c \"ls " + dir + "/" + pattern + "\" 2>/dev/null" +
		" || sh -c \"ls " + dir + "/" + pattern + "\" 2>/dev/null"
	out, err := suScript(30*time.Second, script)
	if err != nil || strings.TrimSpace(out) == "" {
		return []InstalledCert{}, nil
	}

	result := []InstalledCert{}
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if name == "" || strings.Contains(name, "No such file") {
			continue
		}
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		data, err := androidReadCACertPEM(dir, name)
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
			StoreLocation: dir,
			Token:         dir + "|" + name + "|" + certThumbprint(cert),
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
	dir := androidTrustDir()
	if dir == "" {
		return errors.New("无法确定 Android 版本（getprop 失败）")
	}

	var script string
	if dir == androidConscryptDir {
		stage := androidStageDir(brand)
		script = strings.Join([]string{
			"APEX=" + shQuote(androidConscryptDir),
			"STAGE=" + shQuote(stage),
			// Drop a previous bind (this or last install) so the copy below
			// reads the pristine APEX, never the staging directory itself.
			`nsenter -t 1 -m -- umount "$APEX" 2>/dev/null`,
			`umount "$APEX" 2>/dev/null`,
			`true`,
			`rm -rf "$STAGE"`,
			`mkdir -p "$STAGE" || { echo "无法创建暂存目录 $STAGE"; exit 11; }`,
			// The staged set must carry the system roots too; a mount without
			// them would leave the device trusting nothing else.
			`cp "$APEX"/* "$STAGE"/ 2>/dev/null || { echo "复制系统证书失败（$APEX 不可读）"; exit 12; }`,
			`[ "$(ls "$STAGE" | wc -l)" -ge 2 ] || { echo "系统证书复制不完整"; exit 13; }`,
			`cp ` + shQuote(caPath) + ` "$STAGE/` + name + `" || { echo "复制 CA 失败"; exit 14; }`,
			`chmod 644 "$STAGE"/* 2>/dev/null; chown 0:0 "$STAGE"/* 2>/dev/null; true`,
			`nsenter -t 1 -m -- mount --bind "$STAGE" "$APEX" 2>/dev/null || mount --bind "$STAGE" "$APEX" || { echo "bind mount 失败"; exit 15; }`,
			`echo ` + androidInstallConfirm,
		}, "\n")
	} else {
		script = strings.Join([]string{
			"SYS=" + shQuote(androidLegacyCertDir),
			`mount -o rw,remount /system 2>/dev/null || mount -o rw,remount / || { echo "remount /system 失败，设备可能不允许写入系统分区"; exit 21; }`,
			`cp ` + shQuote(caPath) + ` "$SYS/` + name + `" || { mount -o ro,remount /system 2>/dev/null; mount -o ro,remount / 2>/dev/null; echo "复制 CA 失败"; exit 22; }`,
			`chmod 644 "$SYS/` + name + `" || { echo "chmod 失败"; exit 23; }`,
			`mount -o ro,remount /system 2>/dev/null; mount -o ro,remount / 2>/dev/null; true`,
			`echo ` + androidInstallConfirm,
		}, "\n")
	}

	out, err := suScript(90*time.Second, script)
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
	dir := storeLocation
	if dir == "" {
		dir = androidTrustDir()
	}
	if dir == "" {
		return errors.New("无法确定 Android 版本（getprop 失败）")
	}

	// Trust boundary: only delete an anchor that really is this app's CA. The
	// name pattern alone is not proof — verify the thumbprint when the file
	// parses, and require the brand token in the subject.
	if data, err := androidReadCACertPEM(dir, name); err == nil {
		if cert, parseErr := parseAndroidCertPEM(data); parseErr == nil {
			if !isOwnCert(brand, cert) {
				return errors.New("拒绝卸载：该证书不属于本应用")
			}
			if thumbprint != "" && !strings.EqualFold(certThumbprint(cert), thumbprint) {
				return errors.New("拒绝卸载：信任库中的证书与请求的指纹不一致")
			}
		}
	}

	var script string
	if dir == androidConscryptDir {
		stage := androidStageDir(brand)
		script = strings.Join([]string{
			"APEX=" + shQuote(androidConscryptDir),
			"STAGE=" + shQuote(stage),
			`nsenter -t 1 -m -- rm -f "$APEX/` + name + `" 2>/dev/null`,
			`rm -f "$APEX/` + name + `" 2>/dev/null`,
			`rm -f "$STAGE/` + name + `" 2>/dev/null`,
			`true`,
		}, "\n")
	} else {
		script = strings.Join([]string{
			"SYS=" + shQuote(androidLegacyCertDir),
			`mount -o rw,remount /system 2>/dev/null || mount -o rw,remount / || { echo "remount /system 失败"; exit 31; }`,
			`rm -f "$SYS/` + name + `" || { mount -o ro,remount /system 2>/dev/null; mount -o ro,remount / 2>/dev/null; echo "删除证书失败"; exit 32; }`,
			`mount -o ro,remount /system 2>/dev/null; mount -o ro,remount / 2>/dev/null; true`,
		}, "\n")
	}

	if _, err := suScript(60*time.Second, script); err != nil {
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
