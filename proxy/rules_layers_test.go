package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeTestRules(t *testing.T, path string, cfg RulesConfig) {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
}

func writeTestSyncState(t *testing.T, dir string, state rulesSyncState) {
	t.Helper()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("marshal sync state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules_remote_sync.json"), data, 0o644); err != nil {
		t.Fatalf("write sync state: %v", err)
	}
}

func readTestUserRules(t *testing.T, dir string) UserRulesConfig {
	t.Helper()
	var user UserRulesConfig
	data, err := os.ReadFile(filepath.Join(dir, "config.user.json"))
	if err != nil {
		t.Fatalf("read user rules: %v", err)
	}
	if err := json.Unmarshal(data, &user); err != nil {
		t.Fatalf("parse user rules: %v", err)
	}
	return user
}

func hasSiteGroup(groups []SiteGroup, id string) bool {
	for _, g := range groups {
		if g.ID == id {
			return true
		}
	}
	return false
}

// TestLayersFreshInstallTreatsLocalFileAsUpstream covers the no-baseline case:
// a never-updated install keeps its shipped file as the pristine upstream
// layer and starts with an empty user layer.
func TestLayersFreshInstallTreatsLocalFileAsUpstream(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	writeTestRules(t, rulesPath, RulesConfig{
		SiteGroups: []SiteGroup{{ID: "g1", Name: "one", Mode: "mitm", Domains: []string{"one.example"}, Enabled: true}},
		Upstreams:  []Upstream{},
	})

	rm := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if len(rm.userRules.SiteGroups) != 0 {
		t.Errorf("fresh install should start with an empty user layer, got %d groups", len(rm.userRules.SiteGroups))
	}
	if !hasSiteGroup(rm.upstreamRules.SiteGroups, "g1") {
		t.Error("shipped group should live in the upstream layer")
	}
	if _, err := os.Stat(filepath.Join(dir, "config.user.json")); err != nil {
		t.Errorf("migration should create the user layer file: %v", err)
	}
}

// TestLayersMigrationSplitsByBaseline covers migrating a pre-layering merged
// config.json: entries matching the three-way baseline stay upstream, user
// edits and additions go to the user layer, and locally deleted baseline IDs
// become tombstones.
func TestLayersMigrationSplitsByBaseline(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")

	pristine := SiteGroup{ID: "keep", Name: "kept", Mode: "mitm", Domains: []string{"keep.example"}, Enabled: true}
	editedOriginal := SiteGroup{ID: "edit", Name: "original", Mode: "mitm", Domains: []string{"edit.example"}, Enabled: true}
	edited := SiteGroup{ID: "edit", Name: "edited", Mode: "transparent", Domains: []string{"edit.example"}, Enabled: true}
	created := SiteGroup{ID: "mine", Name: "mine", Mode: "quic", Domains: []string{"mine.example"}, Enabled: true}

	writeTestRules(t, rulesPath, RulesConfig{
		SiteGroups: []SiteGroup{pristine, edited, created},
		Upstreams:  []Upstream{},
	})
	writeTestSyncState(t, dir, rulesSyncState{
		RemoteHash: "abc",
		Groups: map[string]string{
			"keep": jsonFingerprint(pristine),
			"edit": jsonFingerprint(editedOriginal),
			"gone": jsonFingerprint(SiteGroup{ID: "gone", Name: "gone", Mode: "mitm", Domains: []string{"gone.example"}}),
		},
	})

	rm := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if !hasSiteGroup(rm.upstreamRules.SiteGroups, "keep") {
		t.Error("pristine group should stay in the upstream layer")
	}
	if hasSiteGroup(rm.upstreamRules.SiteGroups, "edit") || hasSiteGroup(rm.upstreamRules.SiteGroups, "mine") {
		t.Error("user-edited and user-created groups must not be upstream")
	}
	user := readTestUserRules(t, dir)
	if !hasSiteGroup(user.SiteGroups, "edit") || !hasSiteGroup(user.SiteGroups, "mine") {
		t.Error("user-edited and user-created groups should be persisted in the user layer")
	}
	if len(user.DeletedSiteGroups) != 1 || user.DeletedSiteGroups[0] != "gone" {
		t.Errorf("locally deleted baseline group should become a tombstone, got %v", user.DeletedSiteGroups)
	}

	// Effective state keeps the user's view.
	if !hasSiteGroup(rm.siteGroups, "mine") || !hasSiteGroup(rm.siteGroups, "edit") {
		t.Error("effective state lost user groups")
	}
	for _, g := range rm.siteGroups {
		if g.ID == "edit" && g.Name != "edited" {
			t.Errorf("user edit should win, got name %q", g.Name)
		}
	}
}

// TestLayersMergeReplacesUpstreamWholesale covers the remote rules update: the
// upstream layer is replaced wholesale, the user layer file is untouched, and
// user overrides survive.
func TestLayersMergeReplacesUpstreamWholesale(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")

	v1 := RulesConfig{
		SiteGroups: []SiteGroup{
			{ID: "stable", Name: "stable", Mode: "mitm", Domains: []string{"stable.example"}, Enabled: true},
			{ID: "changed", Name: "changed-v1", Mode: "mitm", Domains: []string{"changed.example"}, Enabled: true},
			{ID: "dropped", Name: "dropped", Mode: "mitm", Domains: []string{"dropped.example"}, Enabled: true},
			{ID: "overridden", Name: "overridden-v1", Mode: "mitm", Domains: []string{"overridden.example"}, Enabled: true},
		},
		Upstreams: []Upstream{},
	}
	writeTestRules(t, rulesPath, v1)

	rm := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// User edits one group and adds another.
	if err := rm.UpdateSiteGroup(SiteGroup{ID: "overridden", Name: "my-version", Mode: "quic", Domains: []string{"overridden.example"}, Enabled: true}); err != nil {
		t.Fatalf("UpdateSiteGroup: %v", err)
	}
	if err := rm.AddSiteGroup(SiteGroup{Name: "custom", Mode: "mitm", Domains: []string{"custom.example"}, Enabled: true}); err != nil {
		t.Fatalf("AddSiteGroup: %v", err)
	}
	customID := ""
	for _, g := range rm.siteGroups {
		if g.Name == "custom" {
			customID = g.ID
		}
	}
	if customID == "" {
		t.Fatal("custom group not found")
	}

	userBefore, err := os.ReadFile(filepath.Join(dir, "config.user.json"))
	if err != nil {
		t.Fatalf("read user layer: %v", err)
	}

	// Remote revision v2: "changed" updated, "dropped" removed, "fresh" added.
	v2 := RulesConfig{
		SiteGroups: []SiteGroup{
			{ID: "stable", Name: "stable", Mode: "mitm", Domains: []string{"stable.example"}, Enabled: true},
			{ID: "changed", Name: "changed-v2", Mode: "mitm", Domains: []string{"changed.example"}, Enabled: true},
			{ID: "overridden", Name: "overridden-v2", Mode: "mitm", Domains: []string{"overridden.example"}, Enabled: true},
			{ID: "fresh", Name: "fresh", Mode: "mitm", Domains: []string{"fresh.example"}, Enabled: true},
		},
		Upstreams: []Upstream{},
	}
	summary, err := rm.MergeRemoteRules(v2, "hash-v2")
	if err != nil {
		t.Fatalf("MergeRemoteRules: %v", err)
	}

	if summary.AddedGroups != 1 {
		t.Errorf("expected 1 added group (fresh), got %d (%v)", summary.AddedGroups, summary.Details)
	}
	if summary.UpdatedGroups != 1 {
		t.Errorf("expected 1 updated group (changed), got %d (%v)", summary.UpdatedGroups, summary.Details)
	}
	if summary.KeptGroups != 1 {
		t.Errorf("expected 1 kept group (overridden), got %d (%v)", summary.KeptGroups, summary.Details)
	}
	if summary.RemovedGroups != 1 {
		t.Errorf("expected 1 removed group (dropped), got %d (%v)", summary.RemovedGroups, summary.Details)
	}

	// Effective state after the merge.
	if !hasSiteGroup(rm.siteGroups, "fresh") {
		t.Error("new upstream group missing after merge")
	}
	if hasSiteGroup(rm.siteGroups, "dropped") {
		t.Error("upstream-dropped group should disappear when the user did not override it")
	}
	for _, g := range rm.siteGroups {
		if g.ID == "changed" && g.Name != "changed-v2" {
			t.Errorf("pristine group should follow upstream, got %q", g.Name)
		}
		if g.ID == "overridden" && g.Name != "my-version" {
			t.Errorf("user override lost after merge, got %q", g.Name)
		}
	}
	if !hasSiteGroup(rm.siteGroups, customID) {
		t.Error("user-created group lost after merge")
	}

	// The user layer file is never touched by updates.
	userAfter, err := os.ReadFile(filepath.Join(dir, "config.user.json"))
	if err != nil {
		t.Fatalf("read user layer: %v", err)
	}
	if string(userBefore) != string(userAfter) {
		t.Error("user layer file must not change during a rules update")
	}

	// The upstream layer on disk equals the remote revision.
	var onDisk RulesConfig
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read upstream layer: %v", err)
	}
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("parse upstream layer: %v", err)
	}
	if len(onDisk.SiteGroups) != len(v2.SiteGroups) {
		t.Errorf("upstream layer should hold exactly the remote groups, got %d", len(onDisk.SiteGroups))
	}

	if rm.RemoteRulesHash() != "hash-v2" {
		t.Errorf("remote hash not recorded, got %q", rm.RemoteRulesHash())
	}
}

// TestLayersDeleteUpstreamGroupPersistsAsTombstone covers deleting an upstream
// group: it becomes a tombstone that hides the group across rule updates until
// it is explicitly reverted.
func TestLayersDeleteUpstreamGroupPersistsAsTombstone(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	writeTestRules(t, rulesPath, RulesConfig{
		SiteGroups: []SiteGroup{
			{ID: "victim", Name: "victim", Mode: "mitm", Domains: []string{"victim.example"}, Enabled: true},
			{ID: "other", Name: "other", Mode: "mitm", Domains: []string{"other.example"}, Enabled: true},
		},
		Upstreams: []Upstream{},
	})

	rm := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if err := rm.DeleteSiteGroup("victim"); err != nil {
		t.Fatalf("DeleteSiteGroup: %v", err)
	}
	user := readTestUserRules(t, dir)
	if len(user.DeletedSiteGroups) != 1 || user.DeletedSiteGroups[0] != "victim" {
		t.Fatalf("delete should persist as a tombstone, got %v", user.DeletedSiteGroups)
	}

	// The group must stay hidden across a wholesale upstream refresh.
	remote := RulesConfig{SiteGroups: []SiteGroup{
		{ID: "victim", Name: "victim", Mode: "mitm", Domains: []string{"victim.example"}, Enabled: true},
		{ID: "other", Name: "other", Mode: "mitm", Domains: []string{"other.example"}, Enabled: true},
	}}
	if _, err := rm.MergeRemoteRules(remote, "hash"); err != nil {
		t.Fatalf("MergeRemoteRules: %v", err)
	}
	if hasSiteGroup(rm.siteGroups, "victim") {
		t.Error("tombstoned group resurrected by rules update")
	}

	// Reverting restores it.
	if err := rm.RevertSiteGroupToUpstream("victim"); err != nil {
		t.Fatalf("RevertSiteGroupToUpstream: %v", err)
	}
	if !hasSiteGroup(rm.siteGroups, "victim") {
		t.Error("revert should restore the tombstoned upstream group")
	}
	user = readTestUserRules(t, dir)
	if len(user.DeletedSiteGroups) != 0 {
		t.Errorf("revert should clear the tombstone, got %v", user.DeletedSiteGroups)
	}
}

// TestLayersRevertOverrideAndUserGroup covers the revert semantics: an override
// falls back to the upstream copy, a user-created group is removed.
func TestLayersRevertOverrideAndUserGroup(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	writeTestRules(t, rulesPath, RulesConfig{
		SiteGroups: []SiteGroup{{ID: "base", Name: "base", Mode: "mitm", Domains: []string{"base.example"}, Enabled: true}},
		Upstreams:  []Upstream{},
	})

	rm := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Override "base".
	if err := rm.UpdateSiteGroup(SiteGroup{ID: "base", Name: "mine", Mode: "quic", Domains: []string{"base.example"}, Enabled: true}); err != nil {
		t.Fatalf("UpdateSiteGroup: %v", err)
	}
	// Create a user group.
	if err := rm.AddSiteGroup(SiteGroup{Name: "solo", Mode: "mitm", Domains: []string{"solo.example"}, Enabled: true}); err != nil {
		t.Fatalf("AddSiteGroup: %v", err)
	}
	soloID := ""
	for _, g := range rm.siteGroups {
		if g.Name == "solo" {
			soloID = g.ID
		}
	}

	info := rm.GetRulesLayerInfo()
	if info.SiteGroupLayers["base"] != "override" {
		t.Errorf("edited upstream group should be an override, got %q", info.SiteGroupLayers["base"])
	}
	if info.SiteGroupLayers[soloID] != "user" {
		t.Errorf("user-created group should be layer user, got %q", info.SiteGroupLayers[soloID])
	}

	// Revert the override.
	if err := rm.RevertSiteGroupToUpstream("base"); err != nil {
		t.Fatalf("RevertSiteGroupToUpstream: %v", err)
	}
	for _, g := range rm.siteGroups {
		if g.ID == "base" && (g.Name != "base" || g.Mode != "mitm") {
			t.Errorf("override revert should restore the upstream copy, got %q/%q", g.Name, g.Mode)
		}
	}
	user := readTestUserRules(t, dir)
	if hasSiteGroup(user.SiteGroups, "base") {
		t.Error("override should be dropped from the user layer on revert")
	}

	// Revert the user-created group removes it.
	if err := rm.RevertSiteGroupToUpstream(soloID); err != nil {
		t.Fatalf("RevertSiteGroupToUpstream: %v", err)
	}
	if hasSiteGroup(rm.siteGroups, soloID) {
		t.Error("reverting a user-created group should remove it")
	}

	info = rm.GetRulesLayerInfo()
	if info.SiteGroupLayers["base"] != "upstream" {
		t.Errorf("reverted group should be upstream again, got %q", info.SiteGroupLayers["base"])
	}
}

// TestLayersRoundtripAfterSave proves that saving and reloading reproduce the
// exact same effective state (no drift, no duplicated overrides).
func TestLayersRoundtripAfterSave(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	writeTestRules(t, rulesPath, RulesConfig{
		SiteGroups: []SiteGroup{
			{ID: "a", Name: "a", Mode: "mitm", Domains: []string{"a.example"}, Enabled: true},
			{ID: "b", Name: "b", Mode: "mitm", Domains: []string{"b.example"}, Enabled: true},
		},
		Upstreams: []Upstream{{ID: "u1", Name: "u1", Type: "socks5", Addresses: []string{"socks5://1.2.3.4:1080"}, Enabled: true}},
	})

	rm := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Mutate: edit a, delete b, add c, edit the upstream.
	if err := rm.UpdateSiteGroup(SiteGroup{ID: "a", Name: "a2", Mode: "quic", Domains: []string{"a.example"}, Enabled: true}); err != nil {
		t.Fatalf("UpdateSiteGroup: %v", err)
	}
	if err := rm.DeleteSiteGroup("b"); err != nil {
		t.Fatalf("DeleteSiteGroup: %v", err)
	}
	if err := rm.AddSiteGroup(SiteGroup{Name: "c", Mode: "mitm", Domains: []string{"c.example"}, Enabled: true}); err != nil {
		t.Fatalf("AddSiteGroup: %v", err)
	}
	if err := rm.UpdateUpstream(Upstream{ID: "u1", Name: "u1-renamed", Type: "socks5", Addresses: []string{"socks5://1.2.3.4:1080"}, Enabled: true}); err != nil {
		t.Fatalf("UpdateUpstream: %v", err)
	}

	// Reload from disk into a fresh manager. LoadConfig normalizes the raw
	// mutations (Website inference), so stability is asserted reload-vs-reload.
	rm2 := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm2.LoadConfig(); err != nil {
		t.Fatalf("reload LoadConfig: %v", err)
	}
	after := rm2.effectiveRulesConfig()

	// A second save must be a no-op on the user layer (idempotent diff).
	userBefore := readTestUserRules(t, dir)
	if err := rm2.SaveConfig(); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	userAfter := readTestUserRules(t, dir)
	if !sameJSON(userBefore, userAfter) {
		t.Error("second save should not change the user layer")
	}

	// Reload again: the effective state must be fully stable.
	rm3 := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm3.LoadConfig(); err != nil {
		t.Fatalf("second reload LoadConfig: %v", err)
	}
	after2 := rm3.effectiveRulesConfig()
	if !sameJSON(after, after2) {
		t.Errorf("effective state changed across save/reload:\nbefore=%s\nafter=%s", mustJSON(after), mustJSON(after2))
	}
}

func mustJSON(v interface{}) string {
	data, _ := json.Marshal(v)
	return string(data)
}

// TestLayersApplyAndComputeUnit checks the pure helpers: tombstones hide
// upstream entries, user entries without upstream stand alone, and the diff is
// the exact inverse of the overlay.
func TestLayersApplyAndComputeUnit(t *testing.T) {
	up := RulesConfig{
		SiteGroups: []SiteGroup{
			{ID: "1", Name: "one", Enabled: true},
			{ID: "2", Name: "two", Enabled: true},
		},
	}
	user := UserRulesConfig{
		SiteGroups: []SiteGroup{
			{ID: "2", Name: "two-mine", Website: "two-mine", Enabled: true}, // override
			{ID: "3", Name: "three", Website: "three", Enabled: true},      // standalone
		},
		DeletedSiteGroups: []string{"1"},
	}

	eff := applyUserLayer(up, user)
	if hasSiteGroup(eff.SiteGroups, "1") {
		t.Error("tombstoned group should be hidden")
	}
	if len(eff.SiteGroups) != 2 {
		t.Fatalf("expected 2 effective groups, got %d", len(eff.SiteGroups))
	}
	for _, g := range eff.SiteGroups {
		if g.ID == "2" && g.Name != "two-mine" {
			t.Error("override should win")
		}
	}

	// computeUserLayer(applyUserLayer) must reproduce the user layer when the
	// upstream layer is unchanged (overlay/diff inverse).
	got := computeUserLayer(eff, up)
	if !sameJSON(got.SiteGroups, user.SiteGroups) {
		t.Errorf("diff not inverse of overlay: got %s", mustJSON(got.SiteGroups))
	}
	if !sameJSON(got.DeletedSiteGroups, user.DeletedSiteGroups) {
		t.Errorf("tombstones not reproduced: got %v", got.DeletedSiteGroups)
	}
}
