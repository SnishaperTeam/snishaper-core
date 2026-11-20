package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestListenAddressDefault 验证缺省/空值时 GetListenAddress 返回 127.0.0.1。
func TestListenAddressDefault(t *testing.T) {
	dir := t.TempDir()
	rm := NewRuleManager(filepath.Join(dir, "settings.json"), filepath.Join(dir, "rules.json"))
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := rm.GetListenAddress(); got != "127.0.0.1" {
		t.Fatalf("GetListenAddress = %q, want 127.0.0.1", got)
	}
}

// TestListenAddressSetGetRoundTrip 验证 Get/Set 往返与非法地址拒绝。
func TestListenAddressSetGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	rm := NewRuleManager(filepath.Join(dir, "settings.json"), filepath.Join(dir, "rules.json"))
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if err := rm.SetListenAddress("192.168.1.10"); err != nil {
		t.Fatalf("SetListenAddress: %v", err)
	}
	if got := rm.GetListenAddress(); got != "192.168.1.10" {
		t.Fatalf("GetListenAddress = %q, want 192.168.1.10", got)
	}

	// IPv6 合法。
	if err := rm.SetListenAddress("::1"); err != nil {
		t.Fatalf("SetListenAddress(::1): %v", err)
	}
	if got := rm.GetListenAddress(); got != "::1" {
		t.Fatalf("GetListenAddress = %q, want ::1", got)
	}

	// 通配地址合法。
	if err := rm.SetListenAddress("0.0.0.0"); err != nil {
		t.Fatalf("SetListenAddress(0.0.0.0): %v", err)
	}

	// 非法地址拒绝。
	for _, bad := range []string{"abc", "999.1.1.1", "192.168.1"} {
		if err := rm.SetListenAddress(bad); err == nil {
			t.Fatalf("SetListenAddress(%q) should fail", bad)
		}
	}

	// 空串合法：重置为默认。
	if err := rm.SetListenAddress(""); err != nil {
		t.Fatalf("SetListenAddress(\"\"): %v", err)
	}
	if got := rm.GetListenAddress(); got != "127.0.0.1" {
		t.Fatalf("GetListenAddress after reset = %q, want 127.0.0.1", got)
	}
}

// TestListenAddressPersistReload 验证 listen_address 持久化后重新加载回读。
func TestListenAddressPersistReload(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	rulesPath := filepath.Join(dir, "rules.json")

	rm := NewRuleManager(settingsPath, rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if err := rm.SetListenAddress("10.0.0.8"); err != nil {
		t.Fatalf("SetListenAddress: %v", err)
	}
	if err := rm.SaveConfig(); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	rm2 := NewRuleManager(settingsPath, rulesPath)
	if err := rm2.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig (reload): %v", err)
	}
	if got := rm2.GetListenAddress(); got != "10.0.0.8" {
		t.Fatalf("reloaded GetListenAddress = %q, want 10.0.0.8", got)
	}

	// 空值时省略键（omitempty），重载回落默认。
	if err := rm2.SetListenAddress(""); err != nil {
		t.Fatalf("SetListenAddress(\"\"): %v", err)
	}
	if err := rm2.SaveConfig(); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if containsString(string(data), "listen_address") {
		t.Fatalf("settings.json should omit empty listen_address, got: %s", data)
	}
	rm3 := NewRuleManager(settingsPath, rulesPath)
	if err := rm3.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig (default): %v", err)
	}
	if got := rm3.GetListenAddress(); got != "127.0.0.1" {
		t.Fatalf("default GetListenAddress = %q, want 127.0.0.1", got)
	}
}

// TestIsKnownTopLevelKeyListenAddress 验证 listen_address 被已知键表收录。
func TestIsKnownTopLevelKeyListenAddress(t *testing.T) {
	if !IsKnownTopLevelKey("listen_address") {
		t.Fatal(`IsKnownTopLevelKey("listen_address") = false, want true`)
	}
	if IsKnownTopLevelKey("definitely_not_a_key") {
		t.Fatal(`IsKnownTopLevelKey("definitely_not_a_key") = true, want false`)
	}
}

func containsString(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
