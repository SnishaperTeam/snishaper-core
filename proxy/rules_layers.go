package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Two-layer rules layout (issue #172):
//
//	rules/config.json        upstream layer, replaced wholesale on rule updates
//	rules/config.user.json   user layer, never touched by updates, wins on conflict
//
// Reverting an override is "remove the entry from the user file"; a structural
// override (e.g. a group split into several custom groups) is reverted by
// dropping those groups, which falls back to the upstream group untouched.

// UserRulesConfig is the config.user.json structure: the user layer of the
// rules layout. Entries with the same ID as an upstream entry override it;
// entries without an upstream counterpart stand on their own (this also keeps
// overrides alive when upstream later drops the original). The Deleted* lists
// are tombstones for upstream entries the user deleted: they hide the upstream
// entry until RevertSiteGroupToUpstream / RevertUpstreamConfigToUpstream (or a
// manual user-file edit) removes them.
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

// userRulesPath derives the user layer path from the rules path:
// config.json -> config.user.json.
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

func siteGroupID(g SiteGroup) string     { return g.ID }
func upstreamID(u Upstream) string       { return u.ID }
func dnsNodeID(n DNSNode) string         { return n.ID }
func echProfileID(p ECHProfile) string   { return p.ID }
func nat64ProfileID(p NAT64Profile) string { return p.ID }

// applyUserLayer overlays the user layer on the upstream layer. User entries
// win on conflict; tombstones hide their upstream entries.
func applyUserLayer(up RulesConfig, user UserRulesConfig) RulesConfig {
	return RulesConfig{
		SiteGroups: overlayBy(up.SiteGroups, user.SiteGroups, user.DeletedSiteGroups, siteGroupID),
		Upstreams:  overlayBy(up.Upstreams, user.Upstreams, user.DeletedUpstreams, upstreamID),
		DNSNodes:   overlayBy(up.DNSNodes, user.DNSNodes, user.DeletedDNSNodes, dnsNodeID),
		ECHProfiles: overlayBy(up.ECHProfiles, user.ECHProfiles, user.DeletedECHProfiles, echProfileID),
		NAT64Profiles: overlayBy(up.NAT64Profiles, user.NAT64Profiles, user.DeletedNAT64Profiles, nat64ProfileID),
	}
}

// computeUserLayer derives the user layer by diffing the effective state
// against the pristine upstream layer. This routes every mutation (add, edit,
// delete, import, profile sync) to the right layer automatically: editing an
// upstream entry turns it into a user override, editing a user entry keeps it
// in the user layer, and deleting an upstream entry becomes a tombstone.
// Both sides are normalized on copies first so normalization artifacts (the
// Website/DNSMode fixups LoadConfig applies to the effective state) are not
// misdetected as user overrides; the layers themselves stay pristine.
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

// recomputeUserLayer rebuilds rm.userRules from the effective state. Tombstones
// for IDs the upstream layer no longer carries (e.g. migration-detected
// deletions) cannot be re-derived from the diff, so they are carried over.
func (rm *RuleManager) recomputeUserLayer() {
	user := computeUserLayer(rm.effectiveRulesConfig(), rm.upstreamRules)
	user.DeletedSiteGroups = carryOverTombstones(user.DeletedSiteGroups, rm.userRules.DeletedSiteGroups, rm.upstreamRules.SiteGroups, siteGroupID)
	user.DeletedUpstreams = carryOverTombstones(user.DeletedUpstreams, rm.userRules.DeletedUpstreams, rm.upstreamRules.Upstreams, upstreamID)
	user.DeletedDNSNodes = carryOverTombstones(user.DeletedDNSNodes, rm.userRules.DeletedDNSNodes, rm.upstreamRules.DNSNodes, dnsNodeID)
	user.DeletedECHProfiles = carryOverTombstones(user.DeletedECHProfiles, rm.userRules.DeletedECHProfiles, rm.upstreamRules.ECHProfiles, echProfileID)
	user.DeletedNAT64Profiles = carryOverTombstones(user.DeletedNAT64Profiles, rm.userRules.DeletedNAT64Profiles, rm.upstreamRules.NAT64Profiles, nat64ProfileID)
	rm.userRules = user
}

// carryOverTombstones keeps tombstones whose ID the upstream layer no longer
// lists; they stay harmless (they only mask upstream entries) and keep working
// when upstream re-introduces the entry later.
func carryOverTombstones[T any](fresh, old []string, up []T, id func(T) string) []string {
	if len(old) == 0 {
		return fresh
	}
	upIDs := make(map[string]bool, len(up))
	for _, u := range up {
		upIDs[id(u)] = true
	}
	seen := make(map[string]bool, len(fresh))
	for _, d := range fresh {
		seen[d] = true
	}
	for _, d := range old {
		if !seen[d] && !upIDs[d] {
			fresh = append(fresh, d)
			seen[d] = true
		}
	}
	sort.Strings(fresh)
	return fresh
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

// loadUserRulesConfigFile parses the user layer file; a missing file yields an
// empty layer, a corrupt file is reported but does not brick the app (it is
// rewritten from the effective state on the next save).
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

// migrateLegacyRules splits a pre-layering merged config.json into the
// upstream and user layers. The three-way merge baseline
// (rules_remote_sync.json) holds fingerprints of the last applied remote
// revision: entries still matching it are pristine upstream, everything else
// is a user override or addition. Baseline IDs missing locally were deleted by
// the user and become tombstones. Without a baseline (rules never updated) the
// local file is treated as pristine upstream, matching the old merge behaviour
// for untouched installs.
func (rm *RuleManager) migrateLegacyRules(current RulesConfig) (RulesConfig, UserRulesConfig) {
	baseline := rm.loadSyncState()
	if len(baseline.Groups) == 0 && len(baseline.Upstreams) == 0 {
		return current, UserRulesConfig{}
	}

	up := RulesConfig{}
	user := UserRulesConfig{}

	currentGroupIDs := make(map[string]bool, len(current.SiteGroups))
	for _, g := range current.SiteGroups {
		currentGroupIDs[g.ID] = true
		if fp, ok := baseline.Groups[g.ID]; ok && fp == jsonFingerprint(g) {
			up.SiteGroups = append(up.SiteGroups, g)
			continue
		}
		user.SiteGroups = append(user.SiteGroups, g)
	}
	currentUpstreamIDs := make(map[string]bool, len(current.Upstreams))
	for _, u := range current.Upstreams {
		currentUpstreamIDs[u.ID] = true
		if fp, ok := baseline.Upstreams[u.ID]; ok && fp == jsonFingerprint(u) {
			up.Upstreams = append(up.Upstreams, u)
			continue
		}
		user.Upstreams = append(user.Upstreams, u)
	}

	for id := range baseline.Groups {
		if !currentGroupIDs[id] {
			user.DeletedSiteGroups = append(user.DeletedSiteGroups, id)
		}
	}
	for id := range baseline.Upstreams {
		if !currentUpstreamIDs[id] {
			user.DeletedUpstreams = append(user.DeletedUpstreams, id)
		}
	}
	sort.Strings(user.DeletedSiteGroups)
	sort.Strings(user.DeletedUpstreams)

	// The old merge never updated DNS nodes, ECH profiles or NAT64 profiles
	// (it only added missing ones), so every local entry is kept as-is in the
	// user layer; remote-only entries are still added by applyUserLayer.
	user.DNSNodes = current.DNSNodes
	user.ECHProfiles = current.ECHProfiles
	user.NAT64Profiles = current.NAT64Profiles

	rm.logf("[Config] migrated merged rules file into layers: %d upstream + %d user site groups (%d deleted upstream)",
		len(up.SiteGroups), len(user.SiteGroups), len(user.DeletedSiteGroups))
	return up, user
}

func (rm *RuleManager) saveUserRulesConfig() error {
	path := rm.userRulesPath()
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(rm.userRules, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0644)
}

func (rm *RuleManager) saveUpstreamRulesConfig() error {
	if rm.rulesPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(rm.upstreamRules, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(rm.rulesPath), 0755); err != nil {
		return err
	}
	return writeFileAtomic(rm.rulesPath, data, 0644)
}

// updateRulesFileHash records the combined content hash of both layer files so
// the file watcher can tell real external changes from our own writes.
func (rm *RuleManager) updateRulesFileHash() {
	rm.setRulesHash(rm.combinedRulesFileHash())
}

func (rm *RuleManager) combinedRulesFileHash() string {
	return fileContentHash(rm.rulesPath) + "|" + fileContentHash(rm.userRulesPath())
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
	UserRulesPath     string            `json:"user_rules_path,omitempty"`
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
// upstream, plus the tombstoned (user-deleted) upstream IDs.
func (rm *RuleManager) GetRulesLayerInfo() RulesLayerInfo {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	userGroups := make(map[string]bool, len(rm.userRules.SiteGroups))
	for _, g := range rm.userRules.SiteGroups {
		userGroups[g.ID] = true
	}
	upGroups := make(map[string]bool, len(rm.upstreamRules.SiteGroups))
	for _, g := range rm.upstreamRules.SiteGroups {
		upGroups[g.ID] = true
	}
	userUps := make(map[string]bool, len(rm.userRules.Upstreams))
	for _, u := range rm.userRules.Upstreams {
		userUps[u.ID] = true
	}
	upUps := make(map[string]bool, len(rm.upstreamRules.Upstreams))
	for _, u := range rm.upstreamRules.Upstreams {
		upUps[u.ID] = true
	}

	info := RulesLayerInfo{
		SiteGroupLayers:   make(map[string]string, len(rm.siteGroups)),
		UpstreamLayers:    make(map[string]string, len(rm.upstreams)),
		DeletedSiteGroups: append([]string(nil), rm.userRules.DeletedSiteGroups...),
		DeletedUpstreams:  append([]string(nil), rm.userRules.DeletedUpstreams...),
		UserRulesPath:     rm.userRulesPath(),
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
