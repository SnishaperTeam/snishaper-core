package subscription

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "subscriptions.json")
	return NewStore(path, nil), path
}

func seedEntry(s *Store, id string, builtin bool, domains []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, &Entry{
		ID:         id,
		Name:       id,
		Builtin:    builtin,
		Nodes:      []Node{{Name: "n1", Type: "ss"}},
		SiteGroups: []SiteGroup{{ID: "sub-" + id, Name: id, Mode: "mitm", Domains: domains, Enabled: true}},
		Selection:  map[string]string{},
	})
}

func TestStoreDefaultsToBuiltin(t *testing.T) {
	s, _ := newTestStore(t)

	if s.ActiveID() != DefaultSubscriptionID {
		t.Fatalf("active = %q, want %q", s.ActiveID(), DefaultSubscriptionID)
	}
	entries := s.List()
	if len(entries) != 1 || !entries[0].Builtin {
		t.Fatalf("expected single builtin entry, got %+v", entries)
	}
	if s.ActiveSiteGroups() != nil {
		t.Error("builtin active subscription must return nil site groups (use shipped rules)")
	}
}

func TestStoreAddRejectsBadURL(t *testing.T) {
	s, _ := newTestStore(t)

	if _, err := s.Add("x", "ftp://example.com"); err == nil {
		t.Error("expected error for non-http scheme")
	}
	if _, err := s.Add("x", "  "); err == nil {
		t.Error("expected error for empty url")
	}
}

func TestStoreActivateSwitchesRules(t *testing.T) {
	s, _ := newTestStore(t)
	seedEntry(s, "alpha", false, []string{"a.com"})

	if err := s.SetActive("alpha"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if s.ActiveID() != "alpha" {
		t.Fatalf("active = %q", s.ActiveID())
	}
	groups := s.ActiveSiteGroups()
	if len(groups) != 1 || groups[0].Domains[0] != "a.com" {
		t.Fatalf("site groups = %+v", groups)
	}

	if err := s.SetActive(DefaultSubscriptionID); err != nil {
		t.Fatalf("activate builtin: %v", err)
	}
	if s.ActiveSiteGroups() != nil {
		t.Error("switching back to builtin must return nil")
	}
}

func TestStoreActivateUnknown(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.SetActive("nope"); err == nil {
		t.Error("expected error activating unknown subscription")
	}
}

func TestStoreActivateRejectsEmptyNodes(t *testing.T) {
	s, _ := newTestStore(t)
	entry := s.AddEntryForTest("empty", "https://example.com/sub")

	if err := s.SetActive(entry.ID); err == nil {
		t.Error("activating a zero-node subscription must fail")
	}
	if s.ActiveID() != DefaultSubscriptionID {
		t.Errorf("active = %q, want builtin", s.ActiveID())
	}

	s.SetNodesForTest(entry.ID, []Node{{Name: "n1", Type: "ss"}})
	if err := s.SetActive(entry.ID); err != nil {
		t.Fatalf("activate after adding nodes: %v", err)
	}
}

func TestStoreDeleteFallsBackToBuiltin(t *testing.T) {
	s, _ := newTestStore(t)
	seedEntry(s, "alpha", false, []string{"a.com"})

	if err := s.SetActive("alpha"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if err := s.Delete("alpha"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if s.ActiveID() != DefaultSubscriptionID {
		t.Errorf("active after deleting itself = %q, want builtin", s.ActiveID())
	}
}

func TestStoreCannotDeleteBuiltin(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.Delete(DefaultSubscriptionID); err == nil {
		t.Error("builtin entry must not be deletable")
	}
}

func TestStoreSelectNode(t *testing.T) {
	s, _ := newTestStore(t)
	seedEntry(s, "alpha", false, []string{"a.com"})

	if err := s.SelectNode("alpha", "Proxy", "HK-01"); err != nil {
		t.Fatalf("select: %v", err)
	}
	entry := s.Get("alpha")
	if entry.Selection["Proxy"] != "HK-01" {
		t.Errorf("selection = %+v", entry.Selection)
	}

	if err := s.SelectNode(DefaultSubscriptionID, "Proxy", "HK-01"); err == nil {
		t.Error("builtin subscription must reject node selection")
	}
}

func TestStorePersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subscriptions.json")

	s := NewStore(path, nil)
	seedEntry(s, "alpha", false, []string{"a.com"})
	if err := s.SetActive("alpha"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if err := s.SelectNode("alpha", "Proxy", "JP-02"); err != nil {
		t.Fatalf("select: %v", err)
	}
	if err := s.saveLocked(); err != nil {
		t.Fatalf("save: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("store file not written: %v", err)
	}

	reloaded := NewStore(path, nil)
	if reloaded.ActiveID() != "alpha" {
		t.Errorf("reloaded active = %q, want alpha", reloaded.ActiveID())
	}
	entry := reloaded.Get("alpha")
	if entry == nil {
		t.Fatal("alpha missing after reload")
	}
	if entry.Selection["Proxy"] != "JP-02" {
		t.Errorf("selection lost after reload: %+v", entry.Selection)
	}
	if reloaded.Get(DefaultSubscriptionID) == nil {
		t.Error("builtin entry must be re-injected on load")
	}
}

func TestStoreActivateFailsWhenSubscriptionErrored(t *testing.T) {
	s, _ := newTestStore(t)
	s.mu.Lock()
	s.entries = append(s.entries, &Entry{
		ID:    "broken",
		Name:  "Broken",
		Nodes: []Node{},
		Error: "network unreachable",
	})
	s.mu.Unlock()

	if err := s.SetActive("broken"); err == nil {
		t.Error("expected activation to fail for an errored subscription")
	}
}

func TestPruneSelection(t *testing.T) {
	sel := map[string]string{"Proxy": "a", "Gone": "b"}
	out := pruneSelection(sel, []Group{{Name: "Proxy"}})
	if _, ok := out["Gone"]; ok {
		t.Error("selection for a removed group should be pruned")
	}
	if out["Proxy"] != "a" {
		t.Error("valid selection should be kept")
	}
}
