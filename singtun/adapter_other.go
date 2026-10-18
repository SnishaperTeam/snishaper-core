//go:build !windows

package singtun

import "github.com/SnishaperTeam/snishaper-core/config"

// cleanupStaleAdapters 在非 Windows 平台为 no-op，返回 0 以对齐签名。
func cleanupStaleAdapters(brand config.Brand, logf func(string)) int {
	_, _ = brand, logf
	return 0
}
