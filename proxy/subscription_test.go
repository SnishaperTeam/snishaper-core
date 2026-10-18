package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SnishaperTeam/snishaper-core/subscription"
)

// TestSubscriptionRulesDriveMatchRule proves that rules produced from a Clash
// subscription actually drive the runtime router, and that the built-in rules
// come back when the default subscription is activated.
func TestSubscriptionRulesDriveMatchRule(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	settingsPath := filepath.Join(dir, "settings.json")

	// Seed a built-in rule so we can prove it is replaced and later restored.
	seed := `{"site_groups":[{"id":"builtin-1","name":"builtin.example","mode":"mitm","domains":["builtin.example"],"enabled":true}],"upstreams":[]}`
	if err := os.WriteFile(rulesPath, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	rm := NewRuleManager(settingsPath, rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	store := subscription.NewStore(filepath.Join(dir, "subscriptions.json"), nil)
	rm.SetSubscriptionStore(store)

	// Baseline: built-in rule is live.
	if got := rm.matchRule("builtin.example", "rule").Mode; got != "mitm" {
		t.Fatalf("built-in rule not active, got mode %q", got)
	}

	// Install a subscription-derived rule set directly on the manager.
	rm.mu.Lock()
	rm.siteGroups = []SiteGroup{{
		ID:      "sub-Proxy",
		Name:    "Proxy",
		Mode:    "mitm",
		Domains: []string{"google.com", "youtube.com", "~.+"},
		Enabled: true,
	}}
	rm.mu.Unlock()
	rm.buildRules()

	if got := rm.matchRule("www.google.com", "rule").Mode; got != "mitm" {
		t.Errorf("subscription rule did not match google.com, got %q", got)
	}
	if got := rm.matchRule("youtube.com", "rule").Mode; got != "mitm" {
		t.Errorf("subscription rule did not match youtube.com, got %q", got)
	}
	// The catch-all must apply to domains with no specific rule.
	if got := rm.matchRule("some-random-site.net", "rule").Mode; got != "mitm" {
		t.Errorf("catch-all rule did not apply, got %q", got)
	}
	// A more specific rule must still win over the catch-all.
	rm.mu.Lock()
	rm.siteGroups = append(rm.siteGroups, SiteGroup{
		ID: "sub-DIRECT", Name: "DIRECT", Mode: "direct",
		Domains: []string{"direct.example"}, Enabled: true,
	})
	rm.mu.Unlock()
	rm.buildRules()

	if got := rm.matchRule("direct.example", "rule").Mode; got != "direct" {
		t.Errorf("specific direct rule lost to catch-all, got %q", got)
	}

	// Restoring the default subscription must bring the built-in rules back.
	rm.ApplyActiveSubscriptionRules()
	if got := rm.matchRule("builtin.example", "rule").Mode; got != "mitm" {
		t.Errorf("built-in rule not restored, got %q", got)
	}
	if got := rm.matchRule("www.google.com", "rule").Mode; got == "mitm" {
		t.Error("subscription rule still active after restoring default")
	}
}

// TestSaveRulesConfigSkippedDuringSubscription guards against the subscription
// rules overwriting the shipped rules file.
func TestSaveRulesConfigSkippedDuringSubscription(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	settingsPath := filepath.Join(dir, "settings.json")

	seed := `{"site_groups":[{"id":"builtin-1","name":"builtin.example","mode":"mitm","domains":["builtin.example"],"enabled":true}],"upstreams":[]}`
	if err := os.WriteFile(rulesPath, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rm := NewRuleManager(settingsPath, rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// LoadConfig may normalize the file (it backfills the website field), so
	// capture the post-load bytes as the baseline that must stay untouched.
	baseline, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}

	// Register a subscription through the public path so the store records it
	// as active; a hand-edited siteGroups slice would not trip the guard.
	store := subscription.NewStore(filepath.Join(dir, "subscriptions.json"), nil)
	rm.SetSubscriptionStore(store)

	entry := store.AddEntryForTest("prov", "https://example.com/sub")
	store.SetSiteGroupsForTest(entry.ID, []subscription.SiteGroup{{
		ID: "sub-Proxy", Name: "Proxy", Mode: "mitm",
		Domains: []string{"x.example"}, Enabled: true,
	}})

	if err := rm.ActivateSubscription(entry.ID); err != nil {
		t.Fatalf("ActivateSubscription: %v", err)
	}

	// A save attempt must not touch the file while a subscription is active.
	if err := rm.saveRulesConfig(); err != nil {
		t.Fatalf("saveRulesConfig: %v", err)
	}

	data, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != string(baseline) {
		t.Errorf("rules file was modified by subscription save:\n%s", string(data))
	}

	// Restoring the default subscription must re-enable persistence, and the
	// written file must describe the built-in rules, never the subscription's.
	if err := rm.ActivateSubscription(subscription.DefaultSubscriptionID); err != nil {
		t.Fatalf("restore default: %v", err)
	}
	if err := rm.saveRulesConfig(); err != nil {
		t.Fatalf("save after restore: %v", err)
	}

	final, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if strings.Contains(string(final), "x.example") {
		t.Errorf("subscription rule leaked into the built-in rules file:\n%s", string(final))
	}
	if !strings.Contains(string(final), "builtin.example") {
		t.Errorf("built-in rule missing after restore:\n%s", string(final))
	}
}
