package certmanager

import (
	"strings"
	"testing"

	"github.com/SnishaperTeam/snishaper-core/config"
)

// TestAndroidInstallScriptShape pins the load-bearing lines of the Android
// install script: a tmpfs overlay in the global mount namespace (works on
// read-only /system), the SELinux label without which apps cannot read the
// store, and the per-namespace APEX rebind that makes running apps trust the
// CA without a restart.
func TestAndroidInstallScriptShape(t *testing.T) {
	script := androidInstallScript(config.Brand{}, "/data/local/tmp/ca.crt", "snishaper-ca-abcd1234.0")
	for _, want := range []string{
		`mount -t tmpfs tmpfs /system/etc/security/cacerts`,
		`chcon u:object_r:system_file:s0 /system/etc/security/cacerts`,
		`nsenter -t 1 -m -- sh -c "$GLOBAL"`,
		`pidof zygote`,
		`case "$ZN" in zygote|zygote64) echo "$ZP";; esac`,
		`nsenter --mount=/proc/$Z_PID/ns/mnt`,
		`nsenter --mount=/proc/$PID/ns/mnt`,
		`cp '/data/local/tmp/ca.crt' "$STAGE/snishaper-ca-abcd1234.0"`,
		`echo SNISHAPER_CA_OK`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install script missing %q\nscript:\n%s", want, script)
		}
	}
}

// TestAndroidUninstallScriptCleansEveryScheme guards the unified uninstall:
// the tmpfs/legacy anchor under /system plus the v0.8.7 staging leftovers.
func TestAndroidUninstallScriptCleansEveryScheme(t *testing.T) {
	script := androidUninstallScript(config.Brand{}, "snishaper-ca-abcd1234.0")
	for _, want := range []string{
		`rm -f "$SYS/snishaper-ca-abcd1234.0"`,
		`rm -rf '/data/local/tmp/snishaper-ca-cacerts'`,
		`mount -o rw,remount /system`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("uninstall script missing %q\nscript:\n%s", want, script)
		}
	}
}

// TestAndroidSuCandidatesCoverNonPathRootSolutions pins the absolute su
// locations: KernelSU and APatch do not inject su into the app's $PATH, so
// $PATH lookup alone fails with "executable file not found in $PATH".
func TestAndroidSuCandidatesCoverNonPathRootSolutions(t *testing.T) {
	joined := strings.Join(androidSuCandidates, " ")
	for _, want := range []string{
		"/system/bin/su",
		"/system/xbin/su",
		"/sbin/su",
		"/debug_ramdisk/su",
		"/su/bin/su",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("su candidates missing %q: %v", want, androidSuCandidates)
		}
	}
	if androidSuCandidates[0] != "su" {
		t.Errorf("first su candidate = %q, want the plain $PATH lookup", androidSuCandidates[0])
	}
}

// TestAndroidShellPathPrefixPinsToolDirs guards the PATH prefix prepended to
// every su script: an app process' PATH can be empty (MuMu + KernelSU), and
// without /system/bin early in PATH every toolbox call fails inside the root
// shell. $PATH must stay last so the root solution's own tools still win.
func TestAndroidShellPathPrefixPinsToolDirs(t *testing.T) {
	if !strings.HasPrefix(androidShellPathPrefix, "export PATH=/system/bin:") {
		t.Errorf("path prefix must export /system/bin first: %q", androidShellPathPrefix)
	}
	if !strings.HasSuffix(androidShellPathPrefix, ":$PATH") {
		t.Errorf("path prefix must keep $PATH last: %q", androidShellPathPrefix)
	}
}

// TestAndroidCACertNameIsThumbprintScoped keeps anchor names per generation
// and brand so reinstalls never collide and embedders never see each other.
func TestAndroidCACertNameIsThumbprintScoped(t *testing.T) {
	got := androidCACertName(config.Brand{}, "AA:BB:CC:DD:EE:FF")
	if got != "snishaper-ca-aabbccdd.0" {
		t.Errorf("androidCACertName = %q, want snishaper-ca-aabbccdd.0", got)
	}
	other := androidCACertName(config.Brand{Name: "FlowWeaver"}, "AA:BB:CC:DD:EE:FF")
	if other == got {
		t.Errorf("FlowWeaver anchor %q collides with SniShaper anchor %q", other, got)
	}
}
