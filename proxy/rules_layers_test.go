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

func readTestRulesConfig(t *testing.T, path string) RulesConfig {
	t.Helper()
	var cfg RulesConfig
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return cfg
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

// TestLayersFreshInstallWritesEffectiveAndBackup covers the empty-install
// path: both files are created, no user layer file appears, and the effective
// state starts equal to the backup (empty diff).
func TestLayersFreshInstallWritesEffectiveAndBackup(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")

	rm := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if _, err := os.Stat(rulesPath); err != nil {
		t.Errorf("effective file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.upstream.json")); err != nil {
		t.Errorf("upstream backup missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.user.json")); !os.IsNotExist(err) {
		t.Errorf("retired v0.6 user file must not be created, stat err=%v", err)
	}

	info := rm.GetRulesLayerInfo()
	if len(info.SiteGroupLayers) != 0 {
		t.Errorf("fresh install should have no groups, got %v", info.SiteGroupLayers)
	}
}

// TestLayersNoBaselineTreatsLocalFileAsUpstream covers a never-updated
// install with a shipped config.json: the file stays the effective state and
// is also derived as the pristine upstream backup.
func TestLayersNoBaselineTreatsLocalFileAsUpstream(t *testing.T) {
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

	if !hasSiteGroup(rm.upstreamRules.SiteGroups, "g1") {
		t.Error("shipped group should live in the upstream backup")
	}
	info := rm.GetRulesLayerInfo()
	if info.SiteGroupLayers["g1"] != "upstream" {
		t.Errorf("untouched shipped group should be upstream, got %q", info.SiteGroupLayers["g1"])
	}
}

// TestLayersMigrationSplitsByBaseline covers migrating a pre-layering merged
// config.json: entries matching the three-way baseline become the upstream
// backup, user edits and additions stay only in the effective file, and the
// effective state is preserved as-is.
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

	backup := readTestRulesConfig(t, filepath.Join(dir, "config.upstream.json"))
	if !hasSiteGroup(backup.SiteGroups, "keep") {
		t.Error("pristine group should be in the upstream backup")
	}
	if hasSiteGroup(backup.SiteGroups, "edit") || hasSiteGroup(backup.SiteGroups, "mine") {
		t.Error("user-edited and user-created groups must not be upstream")
	}

	// Effective state keeps the user's view untouched.
	if !hasSiteGroup(rm.siteGroups, "mine") || !hasSiteGroup(rm.siteGroups, "edit") {
		t.Error("effective state lost user groups")
	}
	for _, g := range rm.siteGroups {
		if g.ID == "edit" && g.Name != "edited" {
			t.Errorf("user edit should win, got name %q", g.Name)
		}
	}

	info := rm.GetRulesLayerInfo()
	if info.SiteGroupLayers["keep"] != "upstream" {
		t.Errorf("pristine group should be upstream, got %q", info.SiteGroupLayers["keep"])
	}
	if info.SiteGroupLayers["edit"] != "user" {
		// 基线只存指纹，没有原始上游内容可回退，迁移后的编辑条目诚实地
		// 归为 user 而非 override。
		t.Errorf("baseline-mismatched group should be user (no upstream copy to revert to), got %q", info.SiteGroupLayers["edit"])
	}
	if info.SiteGroupLayers["mine"] != "user" {
		t.Errorf("created group should be user, got %q", info.SiteGroupLayers["mine"])
	}
}

// TestLayersV06LayoutMigratesToEffectivePlusBackup covers the retired v0.6
// layout: config.json (upstream) + config.user.json (user diff) collapse into
// effective config.json + pristine config.upstream.json, and the diff file is
// removed.
func TestLayersV06LayoutMigratesToEffectivePlusBackup(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")

	up := RulesConfig{
		SiteGroups: []SiteGroup{
			{ID: "keep", Name: "keep", Mode: "mitm", Domains: []string{"keep.example"}, Enabled: true},
			{ID: "over", Name: "over-v1", Mode: "mitm", Domains: []string{"over.example"}, Enabled: true},
			{ID: "gone", Name: "gone", Mode: "mitm", Domains: []string{"gone.example"}, Enabled: true},
		},
		Upstreams: []Upstream{},
	}
	user := UserRulesConfig{
		SiteGroups: []SiteGroup{
			{ID: "over", Name: "my-version", Mode: "quic", Domains: []string{"over.example"}, Enabled: true},
		},
		DeletedSiteGroups: []string{"gone"},
	}
	writeTestRules(t, rulesPath, up)
	userData, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		t.Fatalf("marshal user rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.user.json"), userData, 0o644); err != nil {
		t.Fatalf("write user rules: %v", err)
	}

	rm := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "config.user.json")); !os.IsNotExist(err) {
		t.Errorf("v0.6 user file must be removed after migration, stat err=%v", err)
	}

	backup := readTestRulesConfig(t, filepath.Join(dir, "config.upstream.json"))
	if !hasSiteGroup(backup.SiteGroups, "keep") || !hasSiteGroup(backup.SiteGroups, "over") || !hasSiteGroup(backup.SiteGroups, "gone") {
		t.Errorf("backup should hold the old upstream layer verbatim, got %s", mustJSON(backup.SiteGroups))
	}

	effective := readTestRulesConfig(t, rulesPath)
	if !hasSiteGroup(effective.SiteGroups, "keep") {
		t.Error("effective state lost the pristine group")
	}
	if hasSiteGroup(effective.SiteGroups, "gone") {
		t.Error("user-deleted group resurrected by migration")
	}
	for _, g := range effective.SiteGroups {
		if g.ID == "over" && g.Name != "my-version" {
			t.Errorf("user override lost by migration, got %q", g.Name)
		}
	}

	info := rm.GetRulesLayerInfo()
	if info.SiteGroupLayers["keep"] != "upstream" || info.SiteGroupLayers["over"] != "override" {
		t.Errorf("layers wrong after migration: %v", info.SiteGroupLayers)
	}
	if len(info.DeletedSiteGroups) != 1 || info.DeletedSiteGroups[0] != "gone" {
		t.Errorf("deleted group should be a derived tombstone, got %v", info.DeletedSiteGroups)
	}
}

// TestLayersMergeReplacesUpstreamWholesale covers the remote rules update: the
// backup is replaced wholesale, the effective file is rebuilt as new upstream
// + derived user diff, and user overrides survive.
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

	// The backup on disk equals the remote revision.
	backup := readTestRulesConfig(t, filepath.Join(dir, "config.upstream.json"))
	if !sameJSON(backup, v2) {
		t.Errorf("backup should hold exactly the remote revision, got %s", mustJSON(backup.SiteGroups))
	}

	// The effective file on disk matches the rebuilt state (survives reload).
	effectiveOnDisk := readTestRulesConfig(t, rulesPath)
	if !hasSiteGroup(effectiveOnDisk.SiteGroups, customID) || !hasSiteGroup(effectiveOnDisk.SiteGroups, "fresh") {
		t.Errorf("effective file should hold user + new upstream groups, got %s", mustJSON(effectiveOnDisk.SiteGroups))
	}

	if rm.RemoteRulesHash() != "hash-v2" {
		t.Errorf("remote hash not recorded, got %q", rm.RemoteRulesHash())
	}
}

// TestLayersHandEditSurvivesUpdate covers the v0.7 headline: a hand edit of
// config.json is picked up as user state without any marker file and survives
// a wholesale rules update.
func TestLayersHandEditSurvivesUpdate(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "config.json")
	v1 := RulesConfig{
		SiteGroups: []SiteGroup{
			{ID: "a", Name: "a", Mode: "mitm", Domains: []string{"a.example"}, Enabled: true},
			{ID: "b", Name: "b", Mode: "mitm", Domains: []string{"b.example"}, Enabled: true},
		},
		Upstreams: []Upstream{},
	}
	writeTestRules(t, rulesPath, v1)

	rm := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm.LoadConfig(); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Hand-edit the working file: override "a", add "mine".
	handEdited := RulesConfig{
		SiteGroups: []SiteGroup{
			{ID: "a", Name: "a-hand-edited", Mode: "quic", Domains: []string{"a.example"}, Enabled: true},
			{ID: "b", Name: "b", Mode: "mitm", Domains: []string{"b.example"}, Enabled: true},
			{ID: "mine", Name: "mine", Mode: "mitm", Domains: []string{"mine.example"}, Enabled: true},
		},
		Upstreams: []Upstream{},
	}
	writeTestRules(t, rulesPath, handEdited)

	rm2 := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm2.LoadConfig(); err != nil {
		t.Fatalf("reload LoadConfig: %v", err)
	}
	info := rm2.GetRulesLayerInfo()
	if info.SiteGroupLayers["a"] != "override" {
		t.Errorf("hand-edited group should be an override, got %q", info.SiteGroupLayers["a"])
	}
	if info.SiteGroupLayers["mine"] != "user" {
		t.Errorf("hand-added group should be layer user, got %q", info.SiteGroupLayers["mine"])
	}

	// Wholesale update replaces "a" and "b" upstream; the hand edit must win.
	v2 := RulesConfig{
		SiteGroups: []SiteGroup{
			{ID: "a", Name: "a-v2", Mode: "mitm", Domains: []string{"a.example"}, Enabled: true},
			{ID: "b", Name: "b-v2", Mode: "mitm", Domains: []string{"b.example"}, Enabled: true},
		},
		Upstreams: []Upstream{},
	}
	if _, err := rm2.MergeRemoteRules(v2, "hash-v2"); err != nil {
		t.Fatalf("MergeRemoteRules: %v", err)
	}
	for _, g := range rm2.siteGroups {
		if g.ID == "a" && g.Name != "a-hand-edited" {
			t.Errorf("hand edit lost after update, got %q", g.Name)
		}
		if g.ID == "b" && g.Name != "b-v2" {
			t.Errorf("untouched group should follow upstream, got %q", g.Name)
		}
	}
	if !hasSiteGroup(rm2.siteGroups, "mine") {
		t.Error("hand-added group lost after update")
	}
}

// TestLayersDeleteUpstreamGroupPersistsAsTombstone covers deleting an upstream
// group: it disappears from the effective file while the backup keeps it, the
// deletion survives a wholesale upstream refresh until it is explicitly
// reverted.
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
	info := rm.GetRulesLayerInfo()
	if len(info.DeletedSiteGroups) != 1 || info.DeletedSiteGroups[0] != "victim" {
		t.Fatalf("delete should derive a tombstone, got %v", info.DeletedSiteGroups)
	}
	backup := readTestRulesConfig(t, filepath.Join(dir, "config.upstream.json"))
	if !hasSiteGroup(backup.SiteGroups, "victim") {
		t.Error("backup must keep the deleted group so it can be restored")
	}

	// The deletion must survive a wholesale upstream refresh.
	remote := RulesConfig{SiteGroups: []SiteGroup{
		{ID: "victim", Name: "victim", Mode: "mitm", Domains: []string{"victim.example"}, Enabled: true},
		{ID: "other", Name: "other", Mode: "mitm", Domains: []string{"other.example"}, Enabled: true},
	}}
	if _, err := rm.MergeRemoteRules(remote, "hash"); err != nil {
		t.Fatalf("MergeRemoteRules: %v", err)
	}
	if hasSiteGroup(rm.siteGroups, "victim") {
		t.Error("deleted group resurrected by rules update")
	}

	// Reverting restores it.
	if err := rm.RevertSiteGroupToUpstream("victim"); err != nil {
		t.Fatalf("RevertSiteGroupToUpstream: %v", err)
	}
	if !hasSiteGroup(rm.siteGroups, "victim") {
		t.Error("revert should restore the deleted upstream group")
	}
	info = rm.GetRulesLayerInfo()
	if len(info.DeletedSiteGroups) != 0 {
		t.Errorf("revert should clear the tombstone, got %v", info.DeletedSiteGroups)
	}
}

// TestLayersRevertOverrideAndUserGroup covers the revert semantics: an override
// falls back to the backup copy, a user-created group is removed.
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
	effective := readTestRulesConfig(t, rulesPath)
	for _, g := range effective.SiteGroups {
		if g.ID == "base" && g.Name != "base" {
			t.Errorf("effective file should hold the restored copy after revert, got %q", g.Name)
		}
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

// TestLayersEditBackToUpstreamClearsOverride locks the GUI contract from
// issue #172: once a group's user diff is gone (values edited back to the
// upstream copy), its layer falls back to "upstream", so the "modified"
// badge and the revert button disappear without any extra action.
func TestLayersEditBackToUpstreamClearsOverride(t *testing.T) {
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

	// Override, then edit the values back to the upstream copy.
	if err := rm.UpdateSiteGroup(SiteGroup{ID: "base", Name: "mine", Mode: "quic", Domains: []string{"base.example"}, Enabled: true}); err != nil {
		t.Fatalf("UpdateSiteGroup: %v", err)
	}
	if info := rm.GetRulesLayerInfo(); info.SiteGroupLayers["base"] != "override" {
		t.Fatalf("edited group should be an override, got %q", info.SiteGroupLayers["base"])
	}
	if err := rm.UpdateSiteGroup(SiteGroup{ID: "base", Name: "base", Mode: "mitm", Domains: []string{"base.example"}, Enabled: true}); err != nil {
		t.Fatalf("UpdateSiteGroup: %v", err)
	}

	if info := rm.GetRulesLayerInfo(); info.SiteGroupLayers["base"] != "upstream" {
		t.Errorf("editing back to the upstream copy must clear the override, got %q", info.SiteGroupLayers["base"])
	}

	// The cleared state must survive a reload from disk.
	rm2 := NewRuleManager(filepath.Join(dir, "settings.json"), rulesPath)
	if err := rm2.LoadConfig(); err != nil {
		t.Fatalf("reload LoadConfig: %v", err)
	}
	if info := rm2.GetRulesLayerInfo(); info.SiteGroupLayers["base"] != "upstream" {
		t.Errorf("override must stay cleared after reload, got %q", info.SiteGroupLayers["base"])
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

	// A second save must be a no-op on disk (idempotent diff).
	if err := rm2.SaveConfig(); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	afterSave := readTestRulesConfig(t, rulesPath)
	if !sameJSON(after, afterSave) {
		t.Error("second save should not change the effective state")
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
