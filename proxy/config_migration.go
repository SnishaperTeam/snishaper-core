package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CurrentConfigVersion 是本构建理解并写出的配置模式版本。历史文件缺少
// config_version 字段时按 0（legacy）处理，加载时补写当前版本号。
const CurrentConfigVersion = 1

// MigrationReport 描述一次配置加载中发生的迁移与校验结果，供 App 层
// 展示给用户。Changes 是已应用的修改；Warnings 是不影响加载但用户应
// 知道的问题；Errors 非空表示配置无法安全迁移，已保持原样。
type MigrationReport struct {
	FromRulesVersion    int      `json:"from_rules_version"`
	FromSettingsVersion int      `json:"from_settings_version"`
	ToVersion           int      `json:"to_version"`
	Changes             []string `json:"changes,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
	Errors              []string `json:"errors,omitempty"`
	BackupPaths         []string `json:"backup_paths,omitempty"`
}

func (r *MigrationReport) change(format string, args ...any) {
	r.Changes = append(r.Changes, fmt.Sprintf(format, args...))
}

func (r *MigrationReport) warn(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// LoadConfigWithMigration 与 LoadConfig 相同，但返回迁移报告。
func (rm *RuleManager) LoadConfigWithMigration() (MigrationReport, error) {
	report := MigrationReport{ToVersion: CurrentConfigVersion}

	// 1. 探测两个配置文件的版本与未知顶层字段。
	rulesVer, rulesExists, err := probeConfigFile(rm.rulesPath, &report, "rules config")
	if err != nil {
		return report, err
	}
	settingsVer, settingsExists, err := probeConfigFile(rm.settingsPath, &report, "settings config")
	if err != nil {
		return report, err
	}
	report.FromRulesVersion = rulesVer
	report.FromSettingsVersion = settingsVer

	// 2. 未来版本拒绝加载：静默丢弃未知字段会改变行为，必须让用户先
	// 升级程序而不是降级配置。
	if rulesVer > CurrentConfigVersion || settingsVer > CurrentConfigVersion {
		report.Errors = append(report.Errors, fmt.Sprintf(
			"configuration version (rules=%d, settings=%d) is newer than this build supports (%d); upgrade SniShaper first",
			rulesVer, settingsVer, CurrentConfigVersion))
		return report, fmt.Errorf("config version newer than supported")
	}

	// 3. 版本落后的文件在改写前先备份（配置加载自身也可能迁移写回）。
	if rulesExists && rulesVer < CurrentConfigVersion {
		if backup, err := backupConfigFile(rm.rulesPath); err == nil {
			report.BackupPaths = append(report.BackupPaths, backup)
		} else {
			report.Errors = append(report.Errors, "backup rules config failed: "+err.Error())
			return report, err
		}
	}
	if settingsExists && settingsVer < CurrentConfigVersion {
		if backup, err := backupConfigFile(rm.settingsPath); err == nil {
			report.BackupPaths = append(report.BackupPaths, backup)
		} else {
			report.Errors = append(report.Errors, "backup settings config failed: "+err.Error())
			return report, err
		}
	}

	// 4. 正常加载 + 迁移修复。
	if err := rm.loadSettingsConfig(); err != nil {
		return report, err
	}
	if err := rm.loadRulesConfig(); err != nil {
		return report, err
	}
	if err := rm.finishLoadConfig(&report); err != nil {
		return report, err
	}
	return report, nil
}

// probeConfigFile 读取配置文件的 config_version（缺失 = 0）并收集未知
// 顶层字段名。文件不存在时返回 (0, false, nil)。
func probeConfigFile(path string, report *MigrationReport, label string) (int, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return 0, true, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	version := 0
	if v, ok := raw["config_version"]; ok {
		if err := json.Unmarshal(v, &version); err != nil {
			return 0, true, fmt.Errorf("%s has non-numeric config_version: %w", path, err)
		}
	}
	for _, key := range unknownTopLevelKeys(raw, label) {
		report.warn("%s: unknown top-level field %q (from a newer or unsupported version)", label, key)
	}
	return version, true, nil
}

// unknownTopLevelKeys 列出两个配置结构都不认识、也非保留字的顶层键。
func unknownTopLevelKeys(raw map[string]json.RawMessage, label string) []string {
	known := map[string]bool{
		// rules config
		"site_groups": true, "upstreams": true, "dns_nodes": true,
		"ech_profiles": true, "nat64_profiles": true, "ip_pools": true,
		// settings config
		"listen_port": true, "close_to_tray": true, "hibernate_on_close": true,
		"auto_start": true, "show_main_window_on_auto_start": true,
		"auto_enable_proxy_on_auto_start": true, "auto_enable_sysproxy_on_auto_start": true,
		"auto_update_rules": true, "cloudflare_config": true, "auto_routing": true,
		"tun": true, "fragment": true, "language": true, "theme": true,
		"appearance_mode": true, "migration_enabled": true, "migration_server": true,
		"update_channel": true, "download_source": true, "custom_download_source": true,
		// shared
		"config_version": true,
	}
	var unknown []string
	for key := range raw {
		if !known[key] {
			unknown = append(unknown, key)
		}
	}
	// map 顺序不稳定，排序保证报告可复现（也便于测试断言）。
	for i := 1; i < len(unknown); i++ {
		for j := i; j > 0 && unknown[j] < unknown[j-1]; j-- {
			unknown[j], unknown[j-1] = unknown[j-1], unknown[j]
		}
	}
	return unknown
}

// backupConfigFile 在迁移改写前把原文件复制到 <path>.pre-migration.bak。
// 单一固定名：每次迁移覆盖上一次备份，避免备份无限累积；要长期留存的
// 备份由用户自行复制。
func backupConfigFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	backup := path + ".pre-migration.bak"
	if err := os.MkdirAll(filepath.Dir(backup), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(backup, data, 0o644); err != nil {
		return "", err
	}
	return backup, nil
}

// knownModes 是规则模式在本构建中的合法取值。
var knownModes = map[string]bool{
	"direct": true, "mitm": true, "transparent": true, "tls-rf": true,
	"block": true, "quic": true, "warp": true, "server": true,
}

// validateSiteGroups 校验站点组并修复可安全修复的问题。无法安全处理的
// 条目（未知模式、重复 ID）被禁用并记入报告——禁用是显式可见的，比静默
// 改成别的模式更安全。
func (rm *RuleManager) validateSiteGroups(report *MigrationReport) {
	seenIDs := make(map[string]bool, len(rm.siteGroups))
	processSupported := ProcessRoutingSupported()
	for i := range rm.siteGroups {
		sg := &rm.siteGroups[i]
		label := sg.ID
		if label == "" {
			label = sg.Name
		}

		if !knownModes[strings.ToLower(strings.TrimSpace(sg.Mode))] {
			report.warn("site group %q has unknown mode %q; disabled", label, sg.Mode)
			sg.Enabled = false
		}
		if sg.ID != "" {
			if seenIDs[sg.ID] {
				report.warn("duplicate site group ID %q; later copy disabled", sg.ID)
				sg.Enabled = false
			}
			seenIDs[sg.ID] = true
		}
		if sg.Process != "" && !processSupported {
			report.warn("site group %q uses per-application routing, which this platform does not support; the rule will never match", label)
		}
		normalized := normalizeDNSMode(sg.DNSMode)
		if normalized != sg.DNSMode {
			report.change("site group %q: normalized DNS mode %q to %q", label, sg.DNSMode, normalized)
			sg.DNSMode = normalized
		}
	}
}
