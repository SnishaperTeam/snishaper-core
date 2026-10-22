//go:build windows

package certmanager

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/SnishaperTeam/snishaper-core/config"
)

// Windows trust store: certificates live in the CurrentUser/LocalMachine
// Root and CA stores and are manipulated with certutil. Enumeration uses
// PowerShell because certutil output would have to be parsed by hand for the
// subject/expiry fields.

func platformInstallHelp(_ config.Brand) string {
	return "双击 CA 证书文件 -> 安装证书 -> 导入到\"受信任的根证书颁发机构\"（当前用户或本地计算机）"
}

func platformCACertInstalled(brand config.Brand, thumbprint string) bool {
	clean := func(s string) string {
		s = strings.ToLower(s)
		s = strings.ReplaceAll(s, " ", "")
		s = strings.ReplaceAll(s, ":", "")
		return s
	}
	cleanThumb := clean(thumbprint)

	// Run native certutil to check if the cert thumbprint exists in the User
	// Root or CA store. This avoids any PowerShell ExecutionPolicy restriction
	// issues and does not require temp files. The install help tells users they
	// may import to 本地计算机 (LocalMachine), so the machine stores are checked
	// too — otherwise a correct LocalMachine install reads as "untrusted".
	outputRoot, _ := outputHiddenCommand("certutil", "-user", "-store", "root", thumbprint)
	if strings.Contains(clean(string(outputRoot)), cleanThumb) {
		return true
	}
	outputCA, _ := outputHiddenCommand("certutil", "-user", "-store", "ca", thumbprint)
	if strings.Contains(clean(string(outputCA)), cleanThumb) {
		return true
	}
	outputLMRoot, _ := outputHiddenCommand("certutil", "-store", "root", thumbprint)
	if strings.Contains(clean(string(outputLMRoot)), cleanThumb) {
		return true
	}
	outputLMCA, _ := outputHiddenCommand("certutil", "-store", "ca", thumbprint)
	return strings.Contains(clean(string(outputLMCA)), cleanThumb)
}

func platformListCerts(brand config.Brand) ([]InstalledCert, error) {
	// The subject/issuer filter is built from the product name so one
	// application never lists another's root. PowerShell single-quoted strings
	// escape an embedded quote by doubling it.
	pattern := escapePowerShellPattern(brand.Display())
	psScript := `
$pattern = '` + pattern + `'
$stores = @(
  @{ Location = 'CurrentUser'; Name = 'Root' },
  @{ Location = 'CurrentUser'; Name = 'CA' },
  @{ Location = 'LocalMachine'; Name = 'Root' },
  @{ Location = 'LocalMachine'; Name = 'CA' }
)
$result = @()
foreach ($spec in $stores) {
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($spec.Name, $spec.Location)
  try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    foreach ($cert in $store.Certificates) {
      if ($cert.Subject -match $pattern -or $cert.Issuer -match $pattern) {
        $result += [PSCustomObject]@{
          subject = $cert.Subject
          thumbprint = $cert.Thumbprint
          notAfter = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
          storeName = $spec.Name
          storeLocation = $spec.Location
          token = "$($spec.Location)|$($spec.Name)|$($cert.Thumbprint)"
        }
      }
    }
  } finally {
    $store.Close()
  }
}
$result | ConvertTo-Json -Compress
`
	output, err := outputHiddenCommand("powershell", "-NoProfile", "-Command", psScript)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate certificate stores: %w", err)
	}

	text := strings.TrimSpace(string(output))
	if text == "" {
		return []InstalledCert{}, nil
	}

	var certs []InstalledCert
	if strings.HasPrefix(text, "[") {
		if err := json.Unmarshal(output, &certs); err != nil {
			return nil, fmt.Errorf("failed to parse installed certificates: %w", err)
		}
		return certs, nil
	}

	var single InstalledCert
	if err := json.Unmarshal(output, &single); err != nil {
		return nil, fmt.Errorf("failed to parse installed certificate: %w", err)
	}
	return []InstalledCert{single}, nil
}

func platformInstallCA(_ config.Brand, caPath string) error {
	// Use certutil to install to the CurrentUser Root store. This pops up a
	// standard Windows security warning, so it runs visible (not hidden) to
	// keep that interactive dialog in front of the user.
	cmd := exec.Command("certutil", "-user", "-addstore", "root", caPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install CA certificate: %w", err)
	}
	return nil
}

func platformUninstallCert(_ config.Brand, storeLocation, storeName, thumbprint string) error {
	if storeLocation == "" {
		storeLocation = "CurrentUser"
	}
	if storeName == "" {
		storeName = "Root"
	}

	args := []string{}
	if strings.EqualFold(storeLocation, "CurrentUser") {
		args = append(args, "-user")
	}
	args = append(args, "-delstore", storeName, thumbprint)

	if strings.EqualFold(storeLocation, "LocalMachine") {
		return runElevatedCommand("certutil", args...)
	}
	return runHiddenCommand("certutil", args...)
}

// escapePowerShellPattern makes an arbitrary product name safe to embed in a
// PowerShell single-quoted -match pattern: regex metacharacters are escaped and
// a single quote is doubled (the only way to escape it inside '...').
func escapePowerShellPattern(name string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`.`, `\.`,
		`*`, `\*`,
		`+`, `\+`,
		`?`, `\?`,
		`[`, `\[`,
		`]`, `\]`,
		`(`, `\(`,
		`)`, `\)`,
		`{`, `\{`,
		`}`, `\}`,
		`^`, `\^`,
		`$`, `\$`,
		`|`, `\|`,
		`'`, `''`,
	)
	return replacer.Replace(name)
}
