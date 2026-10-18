package evolution

import (
	"encoding/json"
	"testing"

	"github.com/SnishaperTeam/snishaper-core/proxy"
)

// TestGenerateRuleMapsMethodToMode 命中的探测方法必须映射到对应的代理模式，
// 否则应用规则后实际拨号方式与测出的结论不一致。
func TestGenerateRuleMapsMethodToMode(t *testing.T) {
	cases := []struct {
		method   TestMethod
		wantMode string
		wantECH  bool
		wantSni  string
	}{
		{MethodDomainFronting, "mitm", false, "apple.com"},
		{MethodTLSFragment, "tls-rf", false, ""},
		{MethodECH, "mitm", true, ""},
		{MethodQUIC, "quic", false, ""},
	}

	for _, c := range cases {
		rule := GenerateRule("www.example.com", c.method, "apple.com", false)
		if rule.Mode != c.wantMode {
			t.Errorf("%s: mode = %q, want %q", c.method, rule.Mode, c.wantMode)
		}
		if rule.ECHEnabled != c.wantECH {
			t.Errorf("%s: ech = %v, want %v", c.method, rule.ECHEnabled, c.wantECH)
		}
		if rule.SniFake != c.wantSni {
			t.Errorf("%s: sni_fake = %q, want %q", c.method, rule.SniFake, c.wantSni)
		}
		if rule.Name != "www" {
			t.Errorf("%s: name = %q, want %q", c.method, rule.Name, "www")
		}
		if rule.ID == "" {
			t.Errorf("%s: empty rule ID", c.method)
		}
	}
}

// TestToSiteGroupMatchesRulesConfigSchema ToSiteGroup 产出的 map 必须能被
// proxy.SiteGroup 原样反序列化——应用侧就是把它写进 rules/config.json 的
// site_groups 条目，键名一旦漂移规则就会静默失效。
func TestToSiteGroupMatchesRulesConfigSchema(t *testing.T) {
	rule := GenerateRule("api.github.com", MethodECH, "", true)
	rule.UseCFPool = true
	rule.NAT64Enabled = true
	rule.NAT64ProfileID = "nat64-cf"

	raw, err := json.Marshal(rule.ToSiteGroup())
	if err != nil {
		t.Fatalf("marshal site group: %v", err)
	}

	var group proxy.SiteGroup
	if err := json.Unmarshal(raw, &group); err != nil {
		t.Fatalf("unmarshal into proxy.SiteGroup: %v", err)
	}

	if group.ID != rule.ID || group.Name != rule.Name {
		t.Errorf("id/name = %q/%q, want %q/%q", group.ID, group.Name, rule.ID, rule.Name)
	}
	if group.Mode != "mitm" {
		t.Errorf("mode = %q, want mitm", group.Mode)
	}
	if !group.Enabled {
		t.Error("generated rule must be enabled")
	}
	if !group.ECHEnabled || group.ECHProfileID != "legacy-cloudflare" {
		t.Errorf("ech = %v/%q, want true/legacy-cloudflare", group.ECHEnabled, group.ECHProfileID)
	}
	if !group.UseCFPool {
		t.Error("use_cf_pool not propagated")
	}
	if !group.NAT64Enabled || group.NAT64ProfileID != "nat64-cf" {
		t.Errorf("nat64 = %v/%q, want true/nat64-cf", group.NAT64Enabled, group.NAT64ProfileID)
	}
	if len(group.Domains) != 1 || group.Domains[0] != "api.github.com" {
		t.Errorf("domains = %v, want [api.github.com]", group.Domains)
	}
}

// TestToSiteGroupOmitsEmptyOptionalFields 未生效的可选项不能被写进规则，
// 否则会把空 SNI / 空 NAT64 配置当成显式设置下发。
func TestToSiteGroupOmitsEmptyOptionalFields(t *testing.T) {
	rule := GenerateRule("example.com", MethodTLSFragment, "", false)
	group := rule.ToSiteGroup()

	for _, key := range []string{"sni_fake", "ech_enabled", "ech_profile_id", "nat64_enabled", "nat64_profile_id", "use_cf_pool"} {
		if _, ok := group[key]; ok {
			t.Errorf("unexpected key %q in generated site group", key)
		}
	}
}

// TestDefaultTestConfig 默认配置是 CLI 与应用侧的共同基线。
func TestDefaultTestConfig(t *testing.T) {
	cfg := DefaultTestConfig()
	if cfg.Timeout <= 0 {
		t.Errorf("timeout = %v, want positive", cfg.Timeout)
	}
	if cfg.Concurrency <= 0 {
		t.Errorf("concurrency = %d, want positive", cfg.Concurrency)
	}
	if len(cfg.DomainFrontingSNIs) == 0 {
		t.Error("domain fronting SNI list must not be empty")
	}
}
