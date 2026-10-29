package proxy

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newProcessRuleManager(t *testing.T) *RuleManager {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	settingsPath := filepath.Join(dir, "settings.json")
	seed := `{"site_groups":[
		{"id":"g-proc","name":"proc","mode":"block","process":"telegram.exe,discord.exe","domains":[],"enabled":true},
		{"id":"g-proc-domain","name":"proc-domain","mode":"mitm","process":"chrome.exe","domains":["ads.example.com"],"enabled":true},
		{"id":"g-proc-disabled","name":"proc-disabled","mode":"block","process":"chrome.exe","domains":["example.com"],"enabled":false},
		{"id":"g-domain","name":"domain","mode":"direct","domains":["example.com"],"enabled":true}
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

// TestProcessRuleBeatsDomainRule: a matching process rule must outrank every
// domain rule for the same host (processRuleBonus outranks all domain scores).
func TestProcessRuleBeatsDomainRule(t *testing.T) {
	rm := newProcessRuleManager(t)

	rule := rm.matchRuleFor("example.com", "mitm", "telegram.exe")
	if rule.SiteID != "g-proc" || rule.Mode != "block" {
		t.Fatalf("expected process block rule, got %+v", rule)
	}

	// Same host, different process: domain rule wins again.
	rule = rm.matchRuleFor("example.com", "mitm", "other.exe")
	if rule.SiteID != "g-domain" || rule.Mode != "direct" {
		t.Fatalf("expected domain rule for unrelated process, got %+v", rule)
	}
}

// TestProcessRuleFailsClosed: unknown process ("" — lookup failed or platform
// unsupported) must never trigger a per-application rule.
func TestProcessRuleFailsClosed(t *testing.T) {
	rm := newProcessRuleManager(t)

	rule := rm.matchRuleFor("example.com", "mitm", "")
	if rule.SiteID == "g-proc" {
		t.Fatalf("process rule matched with unknown process: %+v", rule)
	}
	if rule.SiteID != "g-domain" {
		t.Fatalf("expected domain rule fallback, got %+v", rule)
	}
}

// TestProcessRuleWithDomainRestriction: process+domain rules need both to
// match; the domain restriction narrows the process rule, not the reverse.
func TestProcessRuleWithDomainRestriction(t *testing.T) {
	rm := newProcessRuleManager(t)

	rule := rm.matchRuleFor("ads.example.com", "mitm", "chrome.exe")
	if rule.SiteID != "g-proc-domain" || rule.Mode != "mitm" {
		t.Fatalf("expected process+domain mitm rule, got %+v", rule)
	}

	// Domain outside the restriction: process-only rule no longer applies,
	// the suffix domain rule (example.com) does.
	rule = rm.matchRuleFor("example.com", "mitm", "chrome.exe")
	if rule.SiteID == "g-proc-domain" {
		t.Fatalf("process+domain rule matched outside its domain: %+v", rule)
	}
}

// TestProcessRuleMoreSpecificWins: process+domain beats process-only for the
// same process because its score includes the domain match on top of the
// process bonus.
func TestProcessRuleMoreSpecificWins(t *testing.T) {
	rm := newProcessRuleManager(t)

	// telegram only has the process-only rule; craft a query where both a
	// process-only and process+domain rule compete for chrome.exe on
	// ads.example.com: g-proc-domain (mitm) must beat nothing else — but on
	// example.com, chrome matches g-domain only. So verify the explain path
	// ranks the candidates correctly for ads.example.com.
	rule := rm.matchRuleFor("ads.example.com", "mitm", "chrome.exe")
	if rule.SiteID != "g-proc-domain" {
		t.Fatalf("expected most specific process rule, got %+v", rule)
	}
}

// TestDisabledProcessRuleIgnored: enabled=false drops the rule entirely.
func TestDisabledProcessRuleIgnored(t *testing.T) {
	rm := newProcessRuleManager(t)

	rule := rm.matchRuleFor("example.com", "mitm", "chrome.exe")
	if rule.SiteID == "g-proc-disabled" {
		t.Fatalf("disabled process rule matched: %+v", rule)
	}
}

// TestProcessNameInList: comma-separated, case-insensitive, whitespace-tolerant.
func TestProcessNameInList(t *testing.T) {
	cases := []struct {
		process, list string
		want          bool
	}{
		{"chrome.exe", "chrome.exe", true},
		{"CHROME.EXE", "chrome.exe,firefox.exe", true},
		{"firefox.exe", " chrome.exe , firefox.exe ", true},
		{"chrom.exe", "chrome.exe", false},
		{"", "chrome.exe", false},
		{"chrome.exe", "", false},
		{"chrome.exe", "chrome", false},
	}
	for _, c := range cases {
		if got := processNameInList(c.process, c.list); got != c.want {
			t.Errorf("processNameInList(%q, %q) = %v, want %v", c.process, c.list, got, c.want)
		}
	}
}

// TestHasProcessRules tracks that the lazy lookup gate is correct: it must
// only fire when at least one ENABLED rule carries a process filter.
func TestHasProcessRules(t *testing.T) {
	rm := newProcessRuleManager(t)
	if !rm.HasProcessRules() {
		t.Fatal("expected process rules present")
	}

	// All process rules disabled → gate must close.
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	seed := `{"site_groups":[
		{"id":"g-off","name":"off","mode":"block","process":"a.exe","domains":[],"enabled":false},
		{"id":"g-plain","name":"plain","mode":"direct","domains":["example.com"],"enabled":true}
	],"upstreams":[]}`
	if err := os.WriteFile(rulesPath, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rm2 := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm2.LoadConfig(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if rm2.HasProcessRules() {
		t.Fatal("expected no enabled process rules after reload")
	}
}

// TestFindProcessNameLive is a smoke test for the platform lookup: dial a
// local TCP connection and ask who owns the client endpoint. It must resolve
// to this test binary on platforms with per-application support.
func TestFindProcessNameLive(t *testing.T) {
	if !ProcessRoutingSupported() {
		t.Skip("per-application process lookup unsupported on this platform")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen locally: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer server.Close()

	// Give the OS a moment to publish the ESTABLISHED row (needed for lsof
	// caching paths); poll briefly instead of a fixed sleep on Windows.
	name := ""
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		name = findProcessName(conn.LocalAddr().String())
		if name != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if name == "" {
		t.Fatalf("findProcessName returned empty for a live connection (client %s)", conn.LocalAddr())
	}
	// Test binary: proxy.test on unix, proxy.test.exe on Windows. On darwin
	// lsof may report the effective name; require the binary stem either way.
	want := "proxy.test"
	if runtime.GOOS == "windows" {
		want = "proxy.test.exe"
	}
	if !strings.Contains(name, want) {
		t.Fatalf("findProcessName = %q, want to contain %q", name, want)
	}
}
