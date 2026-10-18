package subscription

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEndToEndAgainstHTTPServer exercises the real fetch path against a local
// HTTP server, including the Subscription-Userinfo quota header.
func TestEndToEndAgainstHTTPServer(t *testing.T) {
	yamlBody := []byte(`proxies:
  - name: "HK-01"
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-256-gcm
    password: "pw"
    udp: true
  - name: "JP-Trojan"
    type: trojan
    server: jp.example.com
    port: 443
    password: "pw"
    sni: jp.example.com
proxy-groups:
  - name: Proxy
    type: select
    proxies: ["HK-01", "JP-Trojan"]
  - name: Auto
    type: url-test
    proxies: ["HK-01", "JP-Trojan"]
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN-SUFFIX,youtube.com,Proxy
  - DOMAIN,example.org,DIRECT
  - MATCH,Proxy
`)

	srv := newTestHTTPServer(t, yamlBody, "upload=1073741824; download=5368709120; total=107374182400; expire=1893456000")
	defer srv.Close()

	store := NewStore(filepath.Join(t.TempDir(), "subscriptions.json"), nil)

	entry, err := store.Add("My Provider", srv.URL)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	if entry.NodeCount != 2 {
		t.Errorf("node count = %d, want 2", entry.NodeCount)
	}
	if len(entry.Groups) != 2 {
		t.Errorf("group count = %d, want 2", len(entry.Groups))
	}

	// Quota header must round-trip into the entry.
	if entry.UserInfo.Total != 107374182400 {
		t.Errorf("total = %d", entry.UserInfo.Total)
	}
	wantLeft := int64(107374182400 - 1073741824 - 5368709120)
	if entry.UserInfo.Left() != wantLeft {
		t.Errorf("left = %d, want %d", entry.UserInfo.Left(), wantLeft)
	}
	if entry.UserInfo.ExpireTime != 1893456000 {
		t.Errorf("expire = %d", entry.UserInfo.ExpireTime)
	}

	// Activating must swap in subscription rules, not the shipped ones.
	if err := store.SetActive(entry.ID); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	groups := store.ActiveSiteGroups()
	if len(groups) != 2 {
		t.Fatalf("active site groups = %d, want 2 (Proxy + DIRECT): %+v", len(groups), groups)
	}

	var proxyGroup, directGroup *SiteGroup
	for i := range groups {
		if groups[i].ID == "sub-Proxy" {
			proxyGroup = &groups[i]
		}
		if groups[i].ID == "sub-DIRECT" {
			directGroup = &groups[i]
		}
	}
	if proxyGroup == nil {
		t.Fatal("Proxy group missing")
	}
	if proxyGroup.Mode != "mitm" {
		t.Errorf("Proxy mode = %q, want mitm", proxyGroup.Mode)
	}
	if !hasWildcard(proxyGroup.Domains) {
		t.Errorf("MATCH fallback missing from Proxy group: %v", proxyGroup.Domains)
	}
	if directGroup == nil || directGroup.Mode != "direct" {
		t.Errorf("DIRECT group wrong: %+v", directGroup)
	}

	// Node selection persists.
	if err := store.SelectNode(entry.ID, "Proxy", "JP-Trojan"); err != nil {
		t.Fatalf("SelectNode: %v", err)
	}
	if store.Get(entry.ID).Selection["Proxy"] != "JP-Trojan" {
		t.Error("node selection not stored")
	}

	// Update must preserve the selection and refresh the quota.
	if _, err := store.Update(entry.ID); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if store.Get(entry.ID).Selection["Proxy"] != "JP-Trojan" {
		t.Error("update must preserve node selection")
	}

	// Switching back restores the shipped rules.
	if err := store.SetActive(DefaultSubscriptionID); err != nil {
		t.Fatalf("restore builtin: %v", err)
	}
	if store.ActiveSiteGroups() != nil {
		t.Error("builtin must return nil site groups")
	}
}

func TestEndToEndHTTPError(t *testing.T) {
	srv := newTestHTTPServerStatus(t, 500, []byte("boom"), "")
	defer srv.Close()

	store := NewStore(filepath.Join(t.TempDir(), "subscriptions.json"), nil)
	if _, err := store.Add("Bad", srv.URL); err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestEndToEndNoNodes(t *testing.T) {
	body := []byte("proxies: []\nrules:\n  - MATCH,DIRECT\n")
	srv := newTestHTTPServer(t, body, "")
	defer srv.Close()

	store := NewStore(filepath.Join(t.TempDir(), "subscriptions.json"), nil)
	if _, err := store.Add("Empty", srv.URL); err == nil {
		t.Error("expected error when subscription has no nodes")
	}
}

func TestStoreFileWrittenNextToRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subscriptions.json")
	s := NewStore(path, nil)
	seedEntry(s, "alpha", false, []string{"a.com"})
	if err := s.saveLocked(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("store file missing: %v", err)
	}
}
