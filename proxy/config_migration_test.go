package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// seedConfigPair 写入一对 rules/settings 配置文件。
func seedConfigPair(t *testing.T, dir, rules, settings string) (string, string) {
	t.Helper()
	rulesPath := filepath.Join(dir, "config.json")
	settingsPath := filepath.Join(dir, "settings.json")
	if rules != "" {
		if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
			t.Fatalf("seed rules: %v", err)
		}
	}
	if settings != "" {
		if err := os.WriteFile(settingsPath, []byte(settings), 0o644); err != nil {
			t.Fatalf("seed settings: %v", err)
		}
	}
	return rulesPath, settingsPath
}

// TestMigrationLegacyConfigStampedAndBackedUp: 旧版本配置（无
// config_version 字段）加载成功，文件被备份，保存时补写版本号。
func TestMigrationLegacyConfigStampedAndBackedUp(t *testing.T) {
	dir := t.TempDir()
	rulesPath, settingsPath := seedConfigPair(t, dir,
		`{"site_groups":[{"id":"g1","name":"one","mode":"direct","domains":["example.com"],"enabled":true,"website":"https://example.com"}],"upstreams":[]}`,
		`{"listen_port":"8080"}`)

	rm := NewRuleManager(settingsPath, rulesPath)
	report, err := rm.LoadConfigWithMigration()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if report.FromRulesVersion != 0 || report.FromSettingsVersion != 0 {
		t.Fatalf("expected legacy version 0, got %+v", report)
	}
	if len(report.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", report.Errors)
	}
	if len(report.BackupPaths) != 2 {
		t.Fatalf("expected both configs backed up, got %v", report.BackupPaths)
	}
	for _, p := range report.BackupPaths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("backup missing: %v", err)
		}
	}

	// 保存路径必须补写当前版本号。
	if err := rm.saveRulesConfig(); err != nil {
		t.Fatalf("save rules: %v", err)
	}
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read rules: %v", err)
	}
	var cfg RulesConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse rules: %v", err)
	}
	if cfg.ConfigVersion != CurrentConfigVersion {
		t.Fatalf("config_version = %d, want %d", cfg.ConfigVersion, CurrentConfigVersion)
	}
}

// TestMigrationCurrentVersionNoBackup: 已是当前版本的配置不做备份——
// 备份只在真正发生迁移时产生，避免每次加载都堆积备份。
func TestMigrationCurrentVersionNoBackup(t *testing.T) {
	dir := t.TempDir()
	rulesPath, settingsPath := seedConfigPair(t, dir,
		`{"config_version":`+itoaVersion()+`,"site_groups":[],"upstreams":[]}`,
		`{"config_version":`+itoaVersion()+`,"listen_port":"8080"}`)

	rm := NewRuleManager(settingsPath, rulesPath)
	report, err := rm.LoadConfigWithMigration()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(report.BackupPaths) != 0 {
		t.Fatalf("expected no backups for current version, got %v", report.BackupPaths)
	}
}

func itoaVersion() string {
	return strings.TrimSpace(strings.Replace(strings.TrimSpace("1"), " ", "", -1))
}

// TestMigrationFutureVersionRejected: 比程序支持的版本更新的配置必须拒
// 绝加载且不修改原文件（不得静默丢弃未知字段改变行为）。
func TestMigrationFutureVersionRejected(t *testing.T) {
	dir := t.TempDir()
	future := CurrentConfigVersion + 1
	rulesPath, settingsPath := seedConfigPair(t, dir,
		`{"config_version":`+strconv.Itoa(future)+`,"site_groups":[{"id":"g1","name":"one","mode":"direct","domains":["example.com"],"enabled":true,"website":"https://example.com"}],"upstreams":[]}`,
		`{"listen_port":"8080"}`)

	before, _ := os.ReadFile(rulesPath)
	rm := NewRuleManager(settingsPath, rulesPath)
	report, err := rm.LoadConfigWithMigration()
	if err == nil {
		t.Fatal("future version must fail to load")
	}
	if len(report.Errors) == 0 {
		t.Fatal("report must explain the version error")
	}
	after, _ := os.ReadFile(rulesPath)
	if string(before) != string(after) {
		t.Fatal("rejected config must not be modified")
	}
}

// TestMigrationInvalidModeDisablesGroup: 未知模式不能猜测语义——禁用该组
// 并记入报告，比静默改模式安全。
func TestMigrationInvalidModeDisablesGroup(t *testing.T) {
	dir := t.TempDir()
	rulesPath, settingsPath := seedConfigPair(t, dir,
		`{"site_groups":[
			{"id":"g-bad","name":"bad","mode":"sni-split","domains":["a.example.com"],"enabled":true,"website":"https://a.example.com"},
			{"id":"g-ok","name":"ok","mode":"direct","domains":["b.example.com"],"enabled":true,"website":"https://b.example.com"}
		],"upstreams":[]}`,
		`{"listen_port":"8080"}`)

	rm := NewRuleManager(settingsPath, rulesPath)
	report, err := rm.LoadConfigWithMigration()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	found := false
	for _, w := range report.Warnings {
		if strings.Contains(w, "unknown mode") && strings.Contains(w, "sni-split") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unknown-mode warning, got %+v", report)
	}

	// g-bad 禁用后不参与匹配；g-ok 正常。
	for _, sg := range rm.siteGroups {
		if sg.ID == "g-bad" && sg.Enabled {
			t.Fatal("group with unknown mode must be disabled")
		}
	}
	rule := rm.matchRuleFor("b.example.com", "mitm", "")
	if rule.SiteID != "g-ok" {
		t.Fatalf("healthy group must keep matching, got %+v", rule)
	}
}

// TestMigrationDuplicateGroupIDs: 重复 ID 的后续副本禁用并警告。
func TestMigrationDuplicateGroupIDs(t *testing.T) {
	dir := t.TempDir()
	rulesPath, settingsPath := seedConfigPair(t, dir,
		`{"site_groups":[
			{"id":"g-dup","name":"first","mode":"block","domains":["dup.example.com"],"enabled":true,"website":"https://dup.example.com"},
			{"id":"g-dup","name":"second","mode":"direct","domains":["dup.example.com"],"enabled":true,"website":"https://dup.example.com"}
		],"upstreams":[]}`,
		`{"listen_port":"8080"}`)

	rm := NewRuleManager(settingsPath, rulesPath)
	report, err := rm.LoadConfigWithMigration()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	found := false
	for _, w := range report.Warnings {
		if strings.Contains(w, "duplicate site group ID") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected duplicate-ID warning, got %+v", report)
	}
	enabled := 0
	for _, sg := range rm.siteGroups {
		if sg.ID == "g-dup" && sg.Enabled {
			enabled++
		}
	}
	if enabled != 1 {
		t.Fatalf("exactly one g-dup must stay enabled, got %d", enabled)
	}
	// 第一个（block）必须胜出——重复副本不得改变先出现者的行为。
	rule := rm.matchRuleFor("dup.example.com", "mitm", "")
	if rule.Mode != "block" {
		t.Fatalf("first duplicate must win, got mode %q", rule.Mode)
	}
}

// TestMigrationUnknownTopLevelFieldWarns: 未知顶层字段（来自更新版本或
// 手工编辑）记入警告。
func TestMigrationUnknownTopLevelFieldWarns(t *testing.T) {
	dir := t.TempDir()
	rulesPath, settingsPath := seedConfigPair(t, dir,
		`{"quantum_routing":true,"site_groups":[],"upstreams":[]}`,
		`{"listen_port":"8080"}`)

	rm := NewRuleManager(settingsPath, rulesPath)
	report, err := rm.LoadConfigWithMigration()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	found := false
	for _, w := range report.Warnings {
		if strings.Contains(w, "quantum_routing") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unknown-field warning, got %+v", report)
	}
}

// TestMigrationInvalidDNSModeNormalized: 非法 DNS 模式归一化并记为变更
// （这是安全的归一化，不是行为改变）。
func TestMigrationInvalidDNSModeNormalized(t *testing.T) {
	dir := t.TempDir()
	rulesPath, settingsPath := seedConfigPair(t, dir,
		`{"site_groups":[{"id":"g1","name":"one","mode":"direct","dns_mode":"dns-over-smoke-signal","domains":["example.com"],"enabled":true,"website":"https://example.com"}],"upstreams":[]}`,
		`{"listen_port":"8080"}`)

	rm := NewRuleManager(settingsPath, rulesPath)
	report, err := rm.LoadConfigWithMigration()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	found := false
	for _, c := range report.Changes {
		if strings.Contains(c, "normalized DNS mode") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected DNS mode change note, got %+v", report)
	}
	if got := rm.siteGroups[0].DNSMode; got != "" {
		t.Fatalf("expected normalized dns mode %q, got %q", "", got)
	}
}

// TestMigrationProcessRulePlatformWarning: 不支持按应用分流的平台上，
// 进程规则记入警告；支持的平台上不产生噪声。
func TestMigrationProcessRulePlatformWarning(t *testing.T) {
	dir := t.TempDir()
	rulesPath, settingsPath := seedConfigPair(t, dir,
		`{"site_groups":[{"id":"g-proc","name":"proc","mode":"direct","process":"chrome.exe","domains":[],"enabled":true,"website":"https://example.com"}],"upstreams":[]}`,
		`{"listen_port":"8080"}`)

	rm := NewRuleManager(settingsPath, rulesPath)
	report, err := rm.LoadConfigWithMigration()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	found := false
	for _, w := range report.Warnings {
		if strings.Contains(w, "per-application routing") {
			found = true
		}
	}
	if found == ProcessRoutingSupported() {
		t.Fatalf("platform warning mismatch: supported=%v, warned=%v", ProcessRoutingSupported(), found)
	}
}

// TestMigrationV06LayoutCompatibility: v0.6 双文件布局（config.json +
// config.user.json）作为代表性历史配置，必须继续可加载。
func TestMigrationV06LayoutCompatibility(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	userPath := filepath.Join(dir, "config.user.json")
	settingsPath := filepath.Join(dir, "settings.json")

	base := `{"site_groups":[{"id":"g1","name":"one","mode":"direct","domains":["example.com"],"enabled":true,"website":"https://example.com"}],"upstreams":[]}`
	if err := os.WriteFile(rulesPath, []byte(base), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	user := `{"site_groups":[{"id":"g2","name":"two","mode":"mitm","domains":["added.example.com"],"enabled":true,"website":"https://added.example.com"}]}`
	if err := os.WriteFile(userPath, []byte(user), 0o644); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"listen_port":"8080"}`), 0o644); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	rm := NewRuleManager(settingsPath, rulesPath)
	report, err := rm.LoadConfigWithMigration()
	if err != nil {
		t.Fatalf("load v0.6 layout: %v", err)
	}
	if len(report.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", report.Errors)
	}
	// 用户层的组必须合入有效状态。
	if rule := rm.matchRuleFor("added.example.com", "mitm", ""); rule.SiteID != "g2" {
		t.Fatalf("user-layer group missing after migration, got %+v", rule)
	}
	// 差量文件迁移完成后应被删除。
	if _, err := os.Stat(userPath); !os.IsNotExist(err) {
		t.Fatalf("migrated user file must be removed, stat err=%v", err)
	}
}

// TestMigrationCorruptJSONFailsCleanly: 损坏的 JSON 返回错误而不是 panic
// 或被静默替换成默认配置。
func TestMigrationCorruptJSONFailsCleanly(t *testing.T) {
	dir := t.TempDir()
	rulesPath, settingsPath := seedConfigPair(t, dir,
		`{"site_groups":[ BROKEN`,
		`{"listen_port":"8080"}`)

	rm := NewRuleManager(settingsPath, rulesPath)
	report, err := rm.LoadConfigWithMigration()
	if err == nil {
		t.Fatal("corrupt config must fail")
	}
	if len(report.Errors) != 0 && len(report.BackupPaths) != 0 {
		t.Fatalf("corrupt config must not be treated as a migration: %+v", report)
	}
}
