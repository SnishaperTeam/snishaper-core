package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Layered rules layout (issue #172, v0.7):
//
//	rules/config.json          effective state, hand-editable working file
//	rules/config.upstream.json pristine upstream backup, replaced wholesale
//	                           by rule updates, never normalized
//
// The user diff is not persisted: it is derived on demand by diffing the
// effective state against the backup, so hand edits to config.json land in
// the user layer automatically. A rule update replaces the backup, then
// rebuilds the effective state as new upstream + derived diff (user wins on
// conflict) and rewrites config.json. Reverting an override is "copy the
// entry back from the backup".
//
// Legacy layouts migrate on load in one shot: v0.6 (config.json = pristine
// upstream + config.user.json = user diff) collapses into the pair above;
// pre-layering single files keep config.json as the effective state and get
// their upstream layer derived from the three-way merge baseline.

// UserRulesConfig is the in-memory user diff: entries with the same ID as an
// upstream entry override it; entries without an upstream counterpart stand on
// their own (this also keeps overrides alive when upstream later drops the
// original). The Deleted* lists are tombstones for upstream entries the user
// deleted: they hide the upstream entry until
// RevertSiteGroupToUpstream / RevertUpstreamConfigToUpstream removes them.
// It is also the structure of the retired v0.6 config.user.json, read only
// during migration.
type UserRulesConfig struct {
	SiteGroups    []SiteGroup    `json:"site_groups,omitempty"`
	Upstreams     []Upstream     `json:"upstreams,omitempty"`
	DNSNodes      []DNSNode      `json:"dns_nodes,omitempty"`
	ECHProfiles   []ECHProfile   `json:"ech_profiles,omitempty"`
	NAT64Profiles []NAT64Profile `json:"nat64_profiles,omitempty"`

	DeletedSiteGroups    []string `json:"deleted_site_groups,omitempty"`
	DeletedUpstreams     []string `json:"deleted_upstreams,omitempty"`
	DeletedDNSNodes      []string `json:"deleted_dns_nodes,omitempty"`
	DeletedECHProfiles   []string `json:"deleted_ech_profiles,omitempty"`
	DeletedNAT64Profiles []string `json:"deleted_nat64_profiles,omitempty"`
}

// upstreamRulesPath derives the upstream backup path from the rules path:
// config.json -> config.upstream.json.
func (rm *RuleManager) upstreamRulesPath() string {
	if rm.rulesPath == "" {
		return ""
	}
	ext := filepath.Ext(rm.rulesPath)
	if ext == "" {
		return rm.rulesPath + ".upstream.json"
	}
	return strings.TrimSuffix(rm.rulesPath, ext) + ".upstream" + ext
}

// userRulesPath derives the retired v0.6 user layer path; only read and
// deleted when migrating that layout.
func (rm *RuleManager) userRulesPath() string {
	if rm.rulesPath == "" {
		return ""
	}
	ext := filepath.Ext(rm.rulesPath)
	if ext == "" {
		return rm.rulesPath + ".user.json"
	}
	return strings.TrimSuffix(rm.rulesPath, ext) + ".user" + ext
}

// effectiveRulesConfig snapshots the effective (merged) state.
func (rm *RuleManager) effectiveRulesConfig() RulesConfig {
	return RulesConfig{
		SiteGroups:    rm.siteGroups,
		Upstreams:     rm.upstreams,
		DNSNodes:      rm.dnsNodes,
		ECHProfiles:   rm.echProfiles,
		NAT64Profiles: rm.nat64Profiles,
	}
}

// overlayBy merges user entries over upstream entries by ID. Deleted IDs are
// dropped; user entries without an upstream counterpart are appended in order.
func overlayBy[T any](up, user []T, deleted []string, id func(T) string) []T {
	tomb := make(map[string]bool, len(deleted))
	for _, d := range deleted {
		tomb[d] = true
	}
	userByID := make(map[string]T, len(user))
	for _, x := range user {
		userByID[id(x)] = x
	}
	out := make([]T, 0, len(up)+len(user))
	seen := make(map[string]bool, len(up))
	for _, u := range up {
		k := id(u)
		if tomb[k] {
			continue
		}
		if x, ok := userByID[k]; ok {
			out = append(out, x)
		} else {
			out = append(out, u)
		}
		seen[k] = true
	}
	for _, x := range user {
		k := id(x)
		if !seen[k] && !tomb[k] {
			out = append(out, x)
			seen[k] = true
		}
	}
	return out
}

// diffBy splits the effective entries into user-layer entries (differ from or
// missing in upstream) and tombstones (upstream entries missing from the
// effective state).
func diffBy[T any](effective, up []T, id func(T) string, equal func(a, b T) bool) (kept []T, deleted []string) {
	upByID := make(map[string]T, len(up))
	for _, u := range up {
		upByID[id(u)] = u
	}
	effIDs := make(map[string]bool, len(effective))
	for _, e := range effective {
		effIDs[id(e)] = true
		if u, ok := upByID[id(e)]; ok && equal(u, e) {
			continue
		}
		kept = append(kept, e)
	}
	for _, u := range up {
		if !effIDs[id(u)] {
			deleted = append(deleted, id(u))
		}
	}
	return kept, deleted
}

func siteGroupID(g SiteGroup) string       { return g.ID }
func upstreamID(u Upstream) string         { return u.ID }
func dnsNodeID(n DNSNode) string           { return n.ID }
func echProfileID(p ECHProfile) string     { return p.ID }
func nat64ProfileID(p NAT64Profile) string { return p.ID }

// applyUserLayer overlays the user layer on the upstream layer. User entries
// win on conflict; tombstones hide their upstream entries.
func applyUserLayer(up RulesConfig, user UserRulesConfig) RulesConfig {
	return RulesConfig{
		SiteGroups:    overlayBy(up.SiteGroups, user.SiteGroups, user.DeletedSiteGroups, siteGroupID),
		Upstreams:     overlayBy(up.Upstreams, user.Upstreams, user.DeletedUpstreams, upstreamID),
		DNSNodes:      overlayBy(up.DNSNodes, user.DNSNodes, user.DeletedDNSNodes, dnsNodeID),
		ECHProfiles:   overlayBy(up.ECHProfiles, user.ECHProfiles, user.DeletedECHProfiles, echProfileID),
		NAT64Profiles: overlayBy(up.NAT64Profiles, user.NAT64Profiles, user.DeletedNAT64Profiles, nat64ProfileID),
	}
}

// computeUserLayer derives the user layer by diffing the effective state
// against the pristine upstream layer. This routes every mutation (add, edit,
// delete, import, profile sync, hand edit of config.json) to the right layer
// automatically: editing an upstream entry turns it into a user override,
// editing a user entry keeps it in the user layer, and deleting an upstream
// entry becomes a tombstone. Both sides are normalized on copies first so
// normalization artifacts (the Website/DNSMode fixups LoadConfig applies to
// the effective state) are not misdetected as user overrides; the layers
// themselves stay pristine.
func computeUserLayer(effective, up RulesConfig) UserRulesConfig {
	var user UserRulesConfig
	effGroups := append([]SiteGroup(nil), effective.SiteGroups...)
	upGroups := append([]SiteGroup(nil), up.SiteGroups...)
	var sink []ECHProfile
	normalizeSiteGroupsForLayer(effGroups, &sink)
	sink = nil
	normalizeSiteGroupsForLayer(upGroups, &sink)
	user.SiteGroups, user.DeletedSiteGroups = diffBy(effGroups, upGroups, siteGroupID, func(a, b SiteGroup) bool { return sameJSON(a, b) })
	user.Upstreams, user.DeletedUpstreams = diffBy(effective.Upstreams, up.Upstreams, upstreamID, func(a, b Upstream) bool { return sameJSON(a, b) })
	user.DNSNodes, user.DeletedDNSNodes = diffBy(effective.DNSNodes, up.DNSNodes, dnsNodeID, func(a, b DNSNode) bool { return sameJSON(a, b) })
	effProfiles := append([]ECHProfile(nil), effective.ECHProfiles...)
	upProfiles := append([]ECHProfile(nil), up.ECHProfiles...)
	for i := range effProfiles {
		normalizeECHProfile(&effProfiles[i])
	}
	for i := range upProfiles {
		normalizeECHProfile(&upProfiles[i])
	}
	user.ECHProfiles, user.DeletedECHProfiles = diffBy(effProfiles, upProfiles, echProfileID, func(a, b ECHProfile) bool { return sameJSON(a, b) })
	user.NAT64Profiles, user.DeletedNAT64Profiles = diffBy(effective.NAT64Profiles, up.NAT64Profiles, nat64ProfileID, func(a, b NAT64Profile) bool { return sameJSON(a, b) })
	return user
}

// normalizeSiteGroupsForLayer applies the same normalization LoadConfig runs
// on the effective state to a raw layer, so layer diffs are not polluted by
// normalization artifacts (a normalized group would otherwise look like a user
// override of its raw upstream copy).
func normalizeSiteGroupsForLayer(groups []SiteGroup, profiles *[]ECHProfile) {
	for i := range groups {
		groups[i].DNSMode = normalizeDNSMode(groups[i].DNSMode)
		groups[i].Website = strings.TrimSpace(groups[i].Website)
		if groups[i].Website == "" {
			groups[i].Website = inferWebsiteFromSiteGroup(groups[i])
		}
	}
	migrateLegacyECHRules(groups, profiles)
}

// loadUpstreamRulesConfigFile parses the pristine upstream backup; a missing
// file yields (zero, false, nil) so the caller can fall back to migration, a
// corrupt file is a hard error (silently re-deriving the backup from the
// effective state would absorb user edits into the upstream layer).
func loadUpstreamRulesConfigFile(path string) (RulesConfig, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return RulesConfig{}, false, nil
		}
		return RulesConfig{}, false, err
	}
	var cfg RulesConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return RulesConfig{}, true, err
	}
	return cfg, true, nil
}

// loadUserRulesConfigFile parses the retired v0.6 user layer file; a missing
// file yields an empty layer, a corrupt file is reported but does not brick
// the app (migration then treats the effective file as-is).
func loadUserRulesConfigFile(path string) (UserRulesConfig, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return UserRulesConfig{}, false, nil
		}
		return UserRulesConfig{}, false, err
	}
	var user UserRulesConfig
	if err := json.Unmarshal(data, &user); err != nil {
		return UserRulesConfig{}, true, err
	}
	return user, true, nil
}

// copyRulesConfig returns a shallow copy with fresh slices so the upstream
// backup never shares a backing array with the effective state (the mutators
// edit rm.siteGroups in place and would corrupt an aliased backup).
func copyRulesConfig(cfg RulesConfig) RulesConfig {
	return RulesConfig{
		SiteGroups:    append([]SiteGroup(nil), cfg.SiteGroups...),
		Upstreams:     append([]Upstream(nil), cfg.Upstreams...),
		DNSNodes:      append([]DNSNode(nil), cfg.DNSNodes...),
		ECHProfiles:   append([]ECHProfile(nil), cfg.ECHProfiles...),
		NAT64Profiles: append([]NAT64Profile(nil), cfg.NAT64Profiles...),
	}
}

// migrateLegacyRules derives the upstream layer from a pre-layering merged
// config.json (which stays the effective state). Entries matching the
// three-way merge baseline (rules_remote_sync.json, fingerprints of the last
// applied remote revision) are pristine upstream; everything else counts as
// user state and stays only in the effective file. Without a baseline (rules
// never updated) the whole file is treated as pristine upstream, matching the
// old merge behaviour for untouched installs.
func (rm *RuleManager) migrateLegacyRules(current RulesConfig) RulesConfig {
	baseline := rm.loadSyncState()
	if len(baseline.Groups) == 0 && len(baseline.Upstreams) == 0 {
		return copyRulesConfig(current)
	}

	up := RulesConfig{}
	for _, g := range current.SiteGroups {
		if fp, ok := baseline.Groups[g.ID]; ok && fp == jsonFingerprint(g) {
			up.SiteGroups = append(up.SiteGroups, g)
		}
	}
	for _, u := range current.Upstreams {
		if fp, ok := baseline.Upstreams[u.ID]; ok && fp == jsonFingerprint(u) {
			up.Upstreams = append(up.Upstreams, u)
		}
	}
	rm.logf("[Config] derived upstream layer from merged rules file: %d of %d site groups pristine",
		len(up.SiteGroups), len(current.SiteGroups))
	return up
}

// writeRulesConfigFile marshals cfg to path; callers must hold rm.mu.
func writeRulesConfigFile(path string, cfg RulesConfig) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0644)
}

// saveEffectiveRulesConfig persists the effective state to config.json;
// callers must hold rm.mu.
func (rm *RuleManager) saveEffectiveRulesConfig() error {
	return writeRulesConfigFile(rm.rulesPath, rm.effectiveRulesConfig())
}

// saveUpstreamRulesConfig persists the pristine upstream layer to
// config.upstream.json; callers must hold rm.mu.
func (rm *RuleManager) saveUpstreamRulesConfig() error {
	return writeRulesConfigFile(rm.upstreamRulesPath(), rm.upstreamRules)
}

// updateRulesFileHash records the combined content hash of both rules files so
// the file watcher can tell real external changes from our own writes.
func (rm *RuleManager) updateRulesFileHash() {
	rm.setRulesHash(rm.combinedRulesFileHash())
}

func (rm *RuleManager) combinedRulesFileHash() string {
	return fileContentHash(rm.rulesPath) + "|" + fileContentHash(rm.upstreamRulesPath())
}

// RulesLayerInfo reports which layer each effective rule belongs to, so the
// GUI can mark user edits and offer "revert to upstream".
type RulesLayerInfo struct {
	// SiteGroupLayers maps effective site group IDs to "upstream", "override"
	// (user layer, upstream counterpart exists) or "user" (user-created).
	SiteGroupLayers map[string]string `json:"site_group_layers,omitempty"`
	// UpstreamLayers maps effective upstream IDs to the same values.
	UpstreamLayers    map[string]string `json:"upstream_layers,omitempty"`
	DeletedSiteGroups []string          `json:"deleted_site_groups,omitempty"`
	DeletedUpstreams  []string          `json:"deleted_upstreams,omitempty"`
	UpstreamRulesPath string            `json:"upstream_rules_path,omitempty"`
}

func layerOf(id string, inUser map[string]bool, inUpstream map[string]bool) string {
	switch {
	case inUser[id] && inUpstream[id]:
		return "override"
	case inUser[id]:
		return "user"
	default:
		return "upstream"
	}
}

// GetRulesLayerInfo describes the layer of every effective site group and
// upstream, plus the tombstoned (user-deleted) upstream IDs. The user diff is
// derived on demand from the effective state and the upstream backup.
func (rm *RuleManager) GetRulesLayerInfo() RulesLayerInfo {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	user := computeUserLayer(rm.effectiveRulesConfig(), rm.upstreamRules)
	userGroups := make(map[string]bool, len(user.SiteGroups))
	for _, g := range user.SiteGroups {
		userGroups[g.ID] = true
	}
	upGroups := make(map[string]bool, len(rm.upstreamRules.SiteGroups))
	for _, g := range rm.upstreamRules.SiteGroups {
		upGroups[g.ID] = true
	}
	userUps := make(map[string]bool, len(user.Upstreams))
	for _, u := range user.Upstreams {
		userUps[u.ID] = true
	}
	upUps := make(map[string]bool, len(rm.upstreamRules.Upstreams))
	for _, u := range rm.upstreamRules.Upstreams {
		upUps[u.ID] = true
	}

	info := RulesLayerInfo{
		SiteGroupLayers:   make(map[string]string, len(rm.siteGroups)),
		UpstreamLayers:    make(map[string]string, len(rm.upstreams)),
		DeletedSiteGroups: append([]string(nil), user.DeletedSiteGroups...),
		DeletedUpstreams:  append([]string(nil), user.DeletedUpstreams...),
		UpstreamRulesPath: rm.upstreamRulesPath(),
	}
	for _, g := range rm.siteGroups {
		info.SiteGroupLayers[g.ID] = layerOf(g.ID, userGroups, upGroups)
	}
	for _, u := range rm.upstreams {
		info.UpstreamLayers[u.ID] = layerOf(u.ID, userUps, upUps)
	}
	return info
}

// RevertSiteGroupToUpstream drops the user-layer state of a site group so the
// upstream definition applies again: an override falls back to the shipped
// copy, a tombstoned (deleted) upstream group is restored, and a user-created
// group is removed.
func (rm *RuleManager) RevertSiteGroupToUpstream(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	idx := -1
	for i := range rm.upstreamRules.SiteGroups {
		if rm.upstreamRules.SiteGroups[i].ID == id {
			idx = i
			break
		}
	}
	if idx >= 0 {
		restored := rm.upstreamRules.SiteGroups[idx]
		replaced := false
		for i := range rm.siteGroups {
			if rm.siteGroups[i].ID == id {
				rm.siteGroups[i] = restored
				replaced = true
				break
			}
		}
		if !replaced {
			rm.siteGroups = append(rm.siteGroups, restored)
		}
	} else {
		for i := range rm.siteGroups {
			if rm.siteGroups[i].ID == id {
				rm.siteGroups = append(rm.siteGroups[:i], rm.siteGroups[i+1:]...)
				break
			}
		}
	}
	rm.buildRules()
	return rm.saveRulesConfig()
}

// RevertUpstreamConfigToUpstream is RevertSiteGroupToUpstream for an upstream
// (proxy server) definition.
func (rm *RuleManager) RevertUpstreamConfigToUpstream(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	idx := -1
	for i := range rm.upstreamRules.Upstreams {
		if rm.upstreamRules.Upstreams[i].ID == id {
			idx = i
			break
		}
	}
	if idx >= 0 {
		restored := rm.upstreamRules.Upstreams[idx]
		replaced := false
		for i := range rm.upstreams {
			if rm.upstreams[i].ID == id {
				rm.upstreams[i] = restored
				replaced = true
				break
			}
		}
		if !replaced {
			rm.upstreams = append(rm.upstreams, restored)
		}
	} else {
		for i := range rm.upstreams {
			if rm.upstreams[i].ID == id {
				rm.upstreams = append(rm.upstreams[:i], rm.upstreams[i+1:]...)
				break
			}
		}
	}
	rm.buildRules()
	return rm.saveRulesConfig()
}
