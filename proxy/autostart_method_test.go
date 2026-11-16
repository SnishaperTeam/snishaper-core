package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAutoStartMethodRoundTrip 验证 auto_start_method 设置能持久化并在
// 重新加载后保持；空值（旧配置升级）回落为 "task"。
func TestAutoStartMethodRoundTrip(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	rulesPath := filepath.Join(dir, "rules.json")

	rm := NewRuleManager(settingsPath, rulesPath)
	if err := rm.SetAutoStartMethod("service"); err != nil {
		t.Fatalf("SetAutoStartMethod: %v", err)
	}
	if got := rm.GetAutoStartMethod(); got != "service" {
		t.Fatalf("GetAutoStartMethod = %q, want service", got)
	}

	rm2 := NewRuleManager(settingsPath, rulesPath)
	if err := rm2.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := rm2.GetAutoStartMethod(); got != "service" {
		t.Fatalf("reloaded GetAutoStartMethod = %q, want service", got)
	}

	// 旧配置：没有 auto_start_method 字段时按任务计划程序处理。
	if err := os.WriteFile(settingsPath, []byte(`{"listen_port":"8080"}`), 0644); err != nil {
		t.Fatal(err)
	}
	rm3 := NewRuleManager(settingsPath, rulesPath)
	if err := rm3.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig (legacy): %v", err)
	}
	if got := rm3.GetAutoStartMethod(); got != "task" {
		t.Fatalf("legacy GetAutoStartMethod = %q, want task", got)
	}
}
