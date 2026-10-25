package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/SnishaperTeam/snishaper-core/subscription"
)

// sameJSON reports whether two values serialize to identical JSON.
func sameJSON(a, b interface{}) bool {
	ab, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ab) == string(bb)
}

// jsonFingerprint returns the JSON fingerprint used by the legacy three-way
// merge baseline and the layer migration.
func jsonFingerprint(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return dataHash(data)
}

// RulesMergeSummary counts the changes applied by a rules merge.
type RulesMergeSummary struct {
	AddedGroups      int      `json:"added_groups"`
	UpdatedGroups    int      `json:"updated_groups"`
	KeptGroups       int      `json:"kept_groups"`
	RemovedGroups    int      `json:"removed_groups"`
	AddedUpstreams   int      `json:"added_upstreams"`
	UpdatedUpstreams int      `json:"updated_upstreams"`
	KeptUpstreams    int      `json:"kept_upstreams"`
	RemovedUpstreams int      `json:"removed_upstreams"`
	AddedDNSNodes    int      `json:"added_dns_nodes"`
	AddedECHProfiles int      `json:"added_ech_profiles"`
	AddedNAT64       int      `json:"added_nat64_profiles"`
	Details          []string `json:"details,omitempty"`
}

// Changed reports whether the merge added or updated anything.
func (s RulesMergeSummary) Changed() bool {
	return s.AddedGroups+s.UpdatedGroups+s.RemovedGroups+s.AddedUpstreams+s.UpdatedUpstreams+s.RemovedUpstreams+
		s.AddedDNSNodes+s.AddedECHProfiles+s.AddedNAT64 > 0
}

type rulesSyncState struct {
	RemoteHash string `json:"remote_hash"`
	// Groups/Upstreams 是旧版三方合并留下的指纹表，仅 migrateLegacyRules
	// 迁移时读取；分层模式下不再写入。
	Groups    map[string]string `json:"groups,omitempty"`
	Upstreams map[string]string `json:"upstreams,omitempty"`
}

func (rm *RuleManager) syncStatePath() string {
	return filepath.Join(filepath.Dir(rm.rulesPath), "rules_remote_sync.json")
}

func (rm *RuleManager) loadSyncState() rulesSyncState {
	state := rulesSyncState{}
	data, err := os.ReadFile(rm.syncStatePath())
	if err != nil {
		return state
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return rulesSyncState{}
	}
	if state.Groups == nil {
		state.Groups = map[string]string{}
	}
	if state.Upstreams == nil {
		state.Upstreams = map[string]string{}
	}
	return state
}

func (rm *RuleManager) saveSyncState(state rulesSyncState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(rm.syncStatePath(), data, 0644)
}

// RemoteRulesHash reports the hash of the rules revision that was applied
// last, so callers can skip the whole merge when nothing changed upstream.
func (rm *RuleManager) RemoteRulesHash() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.loadSyncState().RemoteHash
}

// CurrentRulesHash reports the hash of the rules currently in memory, which is
// the combined hash of the two layer files as last written.
func (rm *RuleManager) CurrentRulesHash() string {
	return rm.rulesHashValue()
}

// MergeRemoteRules applies a remote rules revision (issue #172, v0.7): the
// pristine upstream backup (rules/config.upstream.json) is replaced wholesale,
// the user diff is derived from the effective state before the swap, and the
// effective state is rebuilt as new upstream + derived diff (user wins on
// conflict) and rewritten to rules/config.json. Hand edits of the working file
// therefore survive updates exactly like GUI edits.
func (rm *RuleManager) MergeRemoteRules(remote RulesConfig, remoteHash string) (RulesMergeSummary, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	oldUpstream := rm.upstreamRules
	oldEffective := rm.effectiveRulesConfig()

	// 归一化副本：LoadConfig 会给有效状态补全 Website 等字段，合并前后
	// 的有效状态需按同样规则归一化后再比较，避免把归一化差异记为更新。
	oldEffNorm := oldEffective
	oldEffNorm.SiteGroups = append([]SiteGroup(nil), oldEffective.SiteGroups...)
	oldEffNorm.ECHProfiles = append([]ECHProfile(nil), oldEffective.ECHProfiles...)
	var sink []ECHProfile
	normalizeSiteGroupsForLayer(oldEffNorm.SiteGroups, &sink)
	for i := range oldEffNorm.ECHProfiles {
		normalizeECHProfile(&oldEffNorm.ECHProfiles[i])
	}

	// 用户差量在替换备份之前从当前有效状态推导：GUI 的增删改和手编
	// config.json 的改动全部自动落在用户层，更新时优先于上游。
	user := computeUserLayer(oldEffective, oldUpstream)

	rm.upstreamRules = remote
	newEffective := applyUserLayer(remote, user)
	normalizeSiteGroupsForLayer(newEffective.SiteGroups, &newEffective.ECHProfiles)
	for i := range newEffective.ECHProfiles {
		normalizeECHProfile(&newEffective.ECHProfiles[i])
	}

	var sum RulesMergeSummary
	if active := rm.activeSubscriptionID(); active != "" && active != subscription.DefaultSubscriptionID {
		// 订阅视图不受规则更新影响：备份照常整体替换并落盘，生效规则
		// 留到切回默认规则时再从有效状态与备份推导。
		sum.Details = append(sum.Details, "remote revision stored while subscription "+active+" is active; effective rules untouched")
		if !sameJSON(oldUpstream, remote) {
			if err := rm.saveUpstreamRulesConfig(); err != nil {
				return sum, err
			}
			rm.updateRulesFileHash()
		}
	} else {
		sum = summarizeLayers(oldEffNorm, newEffective, oldUpstream, remote, user)
		rm.siteGroups = newEffective.SiteGroups
		rm.upstreams = newEffective.Upstreams
		rm.dnsNodes = newEffective.DNSNodes
		rm.echProfiles = newEffective.ECHProfiles
		rm.nat64Profiles = newEffective.NAT64Profiles
		rm.buildRules()
		// buildRules 之后刷新内置快照，切回默认订阅时恢复的才是最新规则。
		rm.builtinSiteGroups = append([]SiteGroup(nil), rm.siteGroups...)
		if !sameJSON(oldUpstream, remote) {
			if err := rm.saveUpstreamRulesConfig(); err != nil {
				return sum, err
			}
		}
		if err := rm.saveEffectiveRulesConfig(); err != nil {
			return sum, err
		}
		rm.updateRulesFileHash()
	}
	if sum.Changed() {
		rm.triggerConfigSaved()
	}
	return sum, rm.saveSyncState(rulesSyncState{RemoteHash: remoteHash})
}

// summarizeLayers compares the effective state before and after a wholesale
// upstream replacement. User-layer entries that survived an upstream change
// count as kept; entries the upstream dropped count as removed.
func summarizeLayers(oldEff, newEff, oldUp, newUp RulesConfig, user UserRulesConfig) RulesMergeSummary {
	var sum RulesMergeSummary

	userGroups := make(map[string]bool, len(user.SiteGroups))
	for _, g := range user.SiteGroups {
		userGroups[g.ID] = true
	}
	oldGroups := make(map[string]SiteGroup, len(oldEff.SiteGroups))
	for _, g := range oldEff.SiteGroups {
		oldGroups[g.ID] = g
	}
	newGroups := make(map[string]bool, len(newEff.SiteGroups))
	for _, g := range newEff.SiteGroups {
		newGroups[g.ID] = true
	}
	for _, g := range newEff.SiteGroups {
		prev, existed := oldGroups[g.ID]
		if !existed {
			sum.AddedGroups++
			sum.Details = append(sum.Details, "added site group "+g.ID+" ("+g.Name+")")
			continue
		}
		upstreamChanged := !sameJSONByID(oldUp.SiteGroups, newUp.SiteGroups, g.ID, siteGroupID)
		switch {
		case sameJSON(prev, g) && !upstreamChanged:
			// untouched
		case userGroups[g.ID]:
			sum.KeptGroups++
			sum.Details = append(sum.Details, "kept user site group "+g.ID+" ("+g.Name+")")
		default:
			sum.UpdatedGroups++
			sum.Details = append(sum.Details, "updated site group "+g.ID+" ("+g.Name+")")
		}
	}
	for id := range oldGroups {
		if !newGroups[id] {
			sum.RemovedGroups++
			sum.Details = append(sum.Details, "removed site group "+id)
		}
	}

	userUps := make(map[string]bool, len(user.Upstreams))
	for _, u := range user.Upstreams {
		userUps[u.ID] = true
	}
	oldUps := make(map[string]Upstream, len(oldEff.Upstreams))
	for _, u := range oldEff.Upstreams {
		oldUps[u.ID] = u
	}
	newUps := make(map[string]bool, len(newEff.Upstreams))
	for _, u := range newEff.Upstreams {
		newUps[u.ID] = true
	}
	for _, u := range newEff.Upstreams {
		prev, existed := oldUps[u.ID]
		if !existed {
			sum.AddedUpstreams++
			sum.Details = append(sum.Details, "added upstream "+u.ID)
			continue
		}
		upstreamChanged := !sameJSONByID(oldUp.Upstreams, newUp.Upstreams, u.ID, upstreamID)
		switch {
		case sameJSON(prev, u) && !upstreamChanged:
			// untouched
		case userUps[u.ID]:
			sum.KeptUpstreams++
			sum.Details = append(sum.Details, "kept user upstream "+u.ID)
		default:
			sum.UpdatedUpstreams++
			sum.Details = append(sum.Details, "updated upstream "+u.ID)
		}
	}
	for id := range oldUps {
		if !newUps[id] {
			sum.RemovedUpstreams++
			sum.Details = append(sum.Details, "removed upstream "+id)
		}
	}

	oldDNS := make(map[string]bool, len(oldEff.DNSNodes))
	for _, n := range oldEff.DNSNodes {
		oldDNS[n.ID] = true
	}
	for _, n := range newEff.DNSNodes {
		if !oldDNS[n.ID] {
			sum.AddedDNSNodes++
			sum.Details = append(sum.Details, "added DNS node "+n.ID)
		}
	}

	oldECH := make(map[string]bool, len(oldEff.ECHProfiles))
	for _, p := range oldEff.ECHProfiles {
		oldECH[p.ID] = true
	}
	for _, p := range newEff.ECHProfiles {
		if !oldECH[p.ID] {
			sum.AddedECHProfiles++
			sum.Details = append(sum.Details, "added ECH profile "+p.ID)
		}
	}

	oldNAT := make(map[string]bool, len(oldEff.NAT64Profiles))
	for _, p := range oldEff.NAT64Profiles {
		oldNAT[p.ID] = true
	}
	for _, p := range newEff.NAT64Profiles {
		if !oldNAT[p.ID] {
			sum.AddedNAT64++
			sum.Details = append(sum.Details, "added NAT64 profile "+p.ID)
		}
	}

	return sum
}

// sameJSONByID compares the entries with the given ID in two slices.
func sameJSONByID[T any](a, b []T, id string, key func(T) string) bool {
	var av, bv *T
	for i := range a {
		if key(a[i]) == id {
			av = &a[i]
			break
		}
	}
	for i := range b {
		if key(b[i]) == id {
			bv = &b[i]
			break
		}
	}
	if av == nil || bv == nil {
		return av == nil && bv == nil
	}
	return sameJSON(*av, *bv)
}
