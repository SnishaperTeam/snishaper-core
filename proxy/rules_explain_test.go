package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

func newExplainRuleManager(t *testing.T) *RuleManager {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	settingsPath := filepath.Join(dir, "settings.json")
	seed := `{"site_groups":[
		{"id":"g-general","name":"general","mode":"direct","domains":["example.com"],"enabled":true},
		{"id":"g-exact","name":"exact","mode":"mitm","domains":["a.example.com"],"enabled":true},
		{"id":"g-disabled","name":"disabled","mode":"block","domains":["a.example.com"],"enabled":false}
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

func TestExplainMatchPrefersMoreSpecificRule(t *testing.T) {
	rm := newExplainRuleManager(t)

	expl := rm.ExplainMatch("a.example.com", "mitm", "")
	if !expl.Simulated {
		t.Fatal("explanation must be marked simulated")
	}
	if expl.Source != "manual" || expl.SiteID != "g-exact" || expl.Mode != "mitm" {
		t.Fatalf("expected exact manual mitm match, got %+v", expl)
	}
	if len(expl.Candidates) < 2 {
		t.Fatalf("expected both suffix and exact candidates, got %+v", expl.Candidates)
	}
	if expl.Candidates[0].Score < expl.Candidates[1].Score {
		t.Fatalf("candidates must be sorted by score desc: %+v", expl.Candidates)
	}
	if expl.Upstream != "DIRECT" {
		t.Fatalf("expected DIRECT upstream, got %q", expl.Upstream)
	}
}

func TestExplainMatchSuffixFallback(t *testing.T) {
	rm := newExplainRuleManager(t)

	expl := rm.ExplainMatch("b.example.com", "mitm", "")
	if expl.Source != "manual" || expl.SiteID != "g-general" || expl.Mode != "direct" {
		t.Fatalf("expected general rule, got %+v", expl)
	}
}

func TestExplainMatchDefaultDirect(t *testing.T) {
	rm := newExplainRuleManager(t)

	expl := rm.ExplainMatch("nothing-here.invalid", "mitm", "")
	if expl.Source != "default" || expl.Mode != "direct" {
		t.Fatalf("expected default direct, got %+v", expl)
	}
	if len(expl.Notes) == 0 {
		t.Fatal("default match must explain itself in notes")
	}
}

func TestExplainMatchTransparentDowngradesMITM(t *testing.T) {
	rm := newExplainRuleManager(t)

	expl := rm.ExplainMatch("a.example.com", "transparent", "")
	if !expl.Downgraded || expl.Mode != "direct" {
		t.Fatalf("expected mitm rule downgraded to direct under transparent, got %+v", expl)
	}
}

// TestExplainMatchDoesNotEmitRouteEvents locks the contract that a simulated
// query never pollutes the live route-event feed: the feed must stay reserved
// for decisions made for real connections.
func TestExplainMatchDoesNotEmitRouteEvents(t *testing.T) {
	rm := newExplainRuleManager(t)

	var events []string
	rm.SetRouteEventCallback(func(domain, mode string) {
		events = append(events, domain+"/"+mode)
	})

	rm.ExplainMatch("a.example.com", "mitm", "")
	if len(events) != 0 {
		t.Fatalf("simulated query emitted route events: %v", events)
	}

	// Real matching still emits.
	if got := rm.matchRule("a.example.com", "mitm").Mode; got != "mitm" {
		t.Fatalf("real match broke, mode=%q", got)
	}
	if len(events) == 0 {
		t.Fatal("real match must still emit route events")
	}
}
