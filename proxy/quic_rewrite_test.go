package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

// newQUICRuleManager seeds a rules file with one site group carrying a QUIC
// rewrite config and one without, plus nothing for unmatched hosts.
func newQUICRuleManager(t *testing.T) *RuleManager {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	settingsPath := filepath.Join(dir, "settings.json")
	seed := `{"site_groups":[
		{"id":"g-quic","name":"quic","mode":"quic","domains":["quic.example.com"],"enabled":true,
		 "quic":{"reserved_bits":true,"prepend_ack":true}},
		{"id":"g-plain","name":"plain","mode":"quic","domains":["plain.example.com"],"enabled":true}
	],"upstreams":[]}`
	if err := os.WriteFile(rulesPath, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	rm := NewRuleManager(settingsPath, rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return rm
}

// TestMatchQUICStrategies pins the TUN fake-ip UDP contract: a host whose rule
// carries enabled QUIC switches gets those strategies, everything else
// (unconfigured site, unmatched host) gets ok=false and must keep the legacy
// drop-and-TCP-fallback behavior.
func TestMatchQUICStrategies(t *testing.T) {
	rm := newQUICRuleManager(t)

	s, ok := rm.MatchQUICStrategies("quic.example.com")
	if !ok {
		t.Fatal("QUIC-configured site must report ok=true")
	}
	if !s.ReservedBits || !s.PrependACK {
		t.Fatalf("unexpected strategies: %+v", s)
	}
	if s.DecoyCrypto || s.FragmentCrypto || s.DoubleHello || s.PunycodeSNI {
		t.Fatalf("strategies leaked switches that are off in config: %+v", s)
	}

	if _, ok := rm.MatchQUICStrategies("plain.example.com"); ok {
		t.Fatal("site without a quic block must not rewrite")
	}
	if _, ok := rm.MatchQUICStrategies("unknown.example.net"); ok {
		t.Fatal("unmatched host must not rewrite")
	}
}

// TestQUICConfigProjectedIntoRule guards the BuildRules projection: SiteGroup's
// quic block must reach the matched Rule, or the data plane never sees it.
func TestQUICConfigProjectedIntoRule(t *testing.T) {
	rm := newQUICRuleManager(t)

	rule := rm.matchRuleFor("quic.example.com", "quic", "")
	if rule.QUIC == nil || !rule.QUIC.AnyEnabled() {
		t.Fatalf("rule projection missing QUIC config: %+v", rule)
	}
	s := rule.QUIC.Strategies()
	if !s.ReservedBits || !s.PrependACK {
		t.Fatalf("unexpected projected strategies: %+v", s)
	}

	rule = rm.matchRuleFor("plain.example.com", "quic", "")
	if rule.QUIC != nil {
		t.Fatalf("site without a quic block must project a nil QUIC: %+v", rule.QUIC)
	}
}

// TestQUICRewriteConfigNilSafety pins the nil-receiver contract relied on by
// MatchQUICStrategies: a nil config must behave as "nothing enabled".
func TestQUICRewriteConfigNilSafety(t *testing.T) {
	var cfg *QUICRewriteConfig
	if cfg.AnyEnabled() {
		t.Fatal("nil QUICRewriteConfig must not report enabled")
	}
	if s := cfg.Strategies(); s.AnyEnabled() {
		t.Fatal("nil QUICRewriteConfig must yield all-off strategies")
	}
}
