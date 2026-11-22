package certmanager

// Pure builders for the Android su install/uninstall scripts. Deliberately
// NOT behind a //go:build android tag: `go test` must be able to run the
// script-shape assertions on the host. The only caller is
// cert_store_android.go; other platforms pull in a few unused functions, which
// Go permits at package level.

import (
	"strings"

	"github.com/SnishaperTeam/snishaper-core/config"
)

const (
	androidLegacyCertDir  = "/system/etc/security/cacerts"        // tmpfs target on every Android version
	androidConscryptDir   = "/apex/com.android.conscrypt/cacerts" // APEX override, Android >= 14
	androidStageDirRoot   = "/data/local/tmp"
	androidInstallConfirm = "SNISHAPER_CA_OK"
)

// androidSuCandidates are tried in order when plain `su` fails to launch.
// $PATH lookup misses some root solutions: KernelSU and APatch do not always
// inject su into the app process environment, so the absolute locations used
// by each solution are probed directly. /data/adb/* paths are excluded: an
// app process cannot traverse /data/adb regardless of permissions.
var androidSuCandidates = []string{
	"su",
	"/system/bin/su",
	"/system/xbin/su",
	"/sbin/su",
	"/system/system/bin/su",
	"/system/system/xbin/su",
	"/debug_ramdisk/su",
	"/su/bin/su",
}

// androidShellPathPrefix is prepended to every script run through su. KernelSU
// and APatch pass the calling process' environment through verbatim, and an
// Android app process' PATH can be empty or lack /system/bin (seen on MuMu),
// which makes every toolbox lookup inside the root shell fail with
// "id: inaccessible or not found". Appending $PATH keeps any tool the root
// solution itself adds.
const androidShellPathPrefix = "export PATH=/system/bin:/system/xbin:/sbin:/vendor/bin:/product/bin:/system_ext/bin:/odm/bin:$PATH"

// shQuote single-quotes s for the su shell script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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

// androidStageDir is the scratch directory holding the current system trust
// set plus the new anchor while the install swaps them into place.
func androidStageDir(brand config.Brand) string {
	safe := strings.TrimSuffix(caAnchorFileNameFor(brand), ".crt")
	return androidStageDirRoot + "/" + safe + "-cacerts"
}

// androidInstallScript builds the unified install script (httptoolkit
// approach, works on Android 9-15 and on read-only /system partitions):
//
//  1. Stage the current trust set plus the new anchor in $STAGE.
//  2. In the global (init) mount namespace: mount a tmpfs over
//     /system/etc/security/cacerts and move the staged set in, with system
//     ownership, 0644 perms and the system_file SELinux label. Slave mount
//     propagation mirrors the tmpfs into zygote and every app namespace.
//  3. On Android 14+ the conscrypt APEX keeps a private per-process view at
//     $APEX: rebind it onto the tmpfs in our own namespace, in zygote, and in
//     every running app, so newly started and already running apps trust the
//     CA immediately.
//
// The su shell may run in the app's mount namespace (KernelSU/APatch) or in
// init's (Magisk forks from its daemon); `nsenter -t 1 -m` is a no-op in the
// latter case and a namespace hop in the former, so step 2 always lands in
// the global namespace.
func androidInstallScript(brand config.Brand, caPath, name string) string {
	stage := androidStageDir(brand)
	return strings.Join([]string{
		"SYS=" + shQuote(androidLegacyCertDir),
		"APEX=" + shQuote(androidConscryptDir),
		"STAGE=" + shQuote(stage),
		// Stage the current trust set. Reading $APEX from the su shell's own
		// namespace is safe: no install step ever shadows it there, and the
		// fallback covers Android <= 13 where the APEX does not exist.
		`rm -rf "$STAGE" 2>/dev/null`,
		`mkdir -p "$STAGE" || { echo "无法创建暂存目录 $STAGE"; exit 11; }`,
		`chmod 700 "$STAGE" 2>/dev/null`,
		`if [ -d "$APEX" ]; then cp "$APEX"/* "$STAGE"/ 2>/dev/null || { echo "复制系统证书失败（$APEX 不可读）"; exit 12; }`,
		`else cp "$SYS"/* "$STAGE"/ 2>/dev/null || { echo "复制系统证书失败（$SYS 不可读）"; exit 12; }`,
		`fi`,
		`[ "$(ls "$STAGE" | wc -l)" -ge 2 ] || { echo "系统证书复制不完整"; exit 13; }`,
		`cp ` + shQuote(caPath) + ` "$STAGE/` + name + `" || { echo "复制 CA 失败"; exit 14; }`,
		`chown root:root "$STAGE"/* 2>/dev/null`,
		`chmod 644 "$STAGE"/* 2>/dev/null`,
		`true`,
		// Swap the staged set into place in the global mount namespace.
		`GLOBAL='` + androidGlobalInstallScript(stage) + `'`,
		`nsenter -t 1 -m -- sh -c "$GLOBAL" || { echo "全局挂载失败"; exit 15; }`,
		// Rebind every private APEX view (ours, zygote's, each app's) onto the
		// new tmpfs so the CA is trusted immediately, without app restarts.
		`if [ -d "$APEX" ]; then`,
		`REBIND='` + androidRebindScript() + `'`,
		`sh -c "$REBIND" 2>/dev/null`,
		`Z_PIDS="$(pidof zygote 2>/dev/null) $(pidof zygote64 2>/dev/null)"`,
		// Fallback: on some Android 15 builds (e.g. MuMu) toybox pidof does not
		// find zygote, while `ps -o NAME` (argv[0]) still lists it.
		`[ -n "$Z_PIDS" ] || Z_PIDS="$(ps -A -o PID,NAME 2>/dev/null | while read ZP ZN; do case "$ZN" in zygote|zygote64) echo "$ZP";; esac; done)"`,
		`for Z_PID in $Z_PIDS; do`,
		`nsenter --mount=/proc/$Z_PID/ns/mnt -- sh -c "$REBIND" 2>/dev/null`,
		`done`,
		// Children of zygote are the running apps; `ps` prints a PID header,
		// filtered by the numeric guard below.
		`APP_PIDS="$(for Z_PID in $Z_PIDS; do ps -o PID -P "$Z_PID" 2>/dev/null; done)"`,
		`for PID in $APP_PIDS; do`,
		`case "$PID" in ""|*[!0-9]*) continue;; esac`,
		`nsenter --mount=/proc/$PID/ns/mnt -- sh -c "$REBIND" 2>/dev/null &`,
		`done`,
		`wait`,
		`fi`,
		`rm -rf "$STAGE" 2>/dev/null`,
		`echo ` + androidInstallConfirm,
	}, "\n")
}

// androidGlobalInstallScript is the init-namespace part of the install. All
// paths are inlined as literals because the inner `sh -c` does not inherit
// the outer shell's variables. Must not contain single quotes.
func androidGlobalInstallScript(stage string) string {
	sys := androidLegacyCertDir
	return strings.Join([]string{
		// Drop previous tmpfs layers (reinstalls within one boot) so the
		// mount stack cannot grow unboundedly.
		`for i in 1 2 3 4 5; do umount -l ` + sys + ` 2>/dev/null || break; done`,
		`mount -t tmpfs tmpfs ` + sys + ` || { echo "tmpfs 挂载失败"; exit 21; }`,
		`mv ` + stage + `/* ` + sys + `/ || { echo "移入系统证书目录失败"; exit 22; }`,
		`chown root:root ` + sys + `/*`,
		`chmod 644 ` + sys + `/*`,
		// SELinux label: without it denials make the store unreadable to apps.
		`chcon u:object_r:system_file:s0 ` + sys + ` 2>/dev/null`,
		`chcon u:object_r:system_file:s0 ` + sys + `/* 2>/dev/null`,
		`true`,
	}, "\n")
}

// androidRebindScript replaces one namespace's private APEX view with the new
// tmpfs store. Must not contain single quotes (it is assigned inside a
// single-quoted shell variable).
func androidRebindScript() string {
	return `for i in 1 2 3 4 5; do umount -l ` + androidConscryptDir + ` 2>/dev/null || break; done
mount --bind ` + androidLegacyCertDir + ` ` + androidConscryptDir
}

// androidUninstallScript builds the unified uninstall script. Deleting the
// anchor from the global tmpfs is mirrored into every bound mount namespace,
// so no explicit unmount is needed there; unmounting $APEX without an
// immediate rebind would instead strip a namespace's real conscrypt view, so
// it is deliberately avoided.
func androidUninstallScript(brand config.Brand, name string) string {
	return strings.Join([]string{
		"SYS=" + shQuote(androidLegacyCertDir),
		// New scheme: the anchor sits on the global tmpfs; rm propagates to
		// every SYS->APEX bind. Legacy installs wrote straight onto /system:
		// remount rw to remove those.
		`rm -f "$SYS/` + name + `" 2>/dev/null`,
		`if [ -f "$SYS/` + name + `" ]; then`,
		`mount -o rw,remount /system 2>/dev/null || mount -o rw,remount / 2>/dev/null || { echo "remount /system 失败，设备可能不允许写入系统分区"; exit 31; }`,
		`rm -f "$SYS/` + name + `" || { echo "删除证书失败"; exit 32; }`,
		`mount -o ro,remount /system 2>/dev/null; mount -o ro,remount / 2>/dev/null`,
		`true`,
		`fi`,
		// v0.8.7 staging leftovers.
		`rm -rf ` + shQuote(androidStageDir(brand)) + ` 2>/dev/null`,
		`true`,
	}, "\n")
}
