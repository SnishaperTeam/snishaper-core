package proxy

import (
	"sort"
	"strings"
)

// MatchCandidate is one rule that also matched the queried host, together with
// the priority score that decided the winner. Exact matches score 1000+,
// regex patterns 900+, keyword matches 800+ and suffix matches score by
// pattern length; the highest score wins, which is why a longer (more
// specific) rule beats a more general one.
type MatchCandidate struct {
	Domain  string `json:"domain"`
	SiteID  string `json:"site_id,omitempty"`
	Mode    string `json:"mode"`
	Process string `json:"process,omitempty"`
	Score   int    `json:"score"`
}

// MatchExplanation is the simulated decision for a host, produced by the very
// code path that handles real connections (matchRuleDetailed). Simulated is
// always true: this describes what WOULD happen, never what happened.
type MatchExplanation struct {
	Simulated  bool             `json:"simulated"`
	Host       string           `json:"host"`
	Mode       string           `json:"mode"`
	Source     string           `json:"source"` // "manual", "auto" or "default"
	SiteID     string           `json:"site_id,omitempty"`
	RuleDomain string           `json:"rule_domain,omitempty"`
	DNSMode    string           `json:"dns_mode,omitempty"`
	Upstream   string           `json:"upstream,omitempty"`
	SniFake    string           `json:"sni_fake,omitempty"`
	ECHEnabled bool             `json:"ech_enabled"`
	UseCFPool  bool             `json:"use_cf_pool"`
	Downgraded bool             `json:"downgraded"`
	Candidates []MatchCandidate `json:"candidates,omitempty"`
	Notes      []string         `json:"notes,omitempty"`
}

// maxExplanationCandidates bounds the candidate list; the top-scoring rules
// are the ones that matter for "why did this rule win".
const maxExplanationCandidates = 10

// ExplainMatch explains how the rule engine would handle host under the given
// global mode ("mitm", "transparent", ...) from the given client process base
// name ("" = unknown/any). It reuses the real matching pipeline — same scores,
// same process-rule precedence, same auto-routing fallback, same MITM
// downgrade — so the explanation cannot drift from the engine; it only skips
// route-event emission to keep the live route feed free of simulated queries.
func (rm *RuleManager) ExplainMatch(host, mode, process string) MatchExplanation {
	rule, candidates, downgraded := rm.matchRuleDetailed(host, mode, process, true, false)

	upstream := strings.TrimSpace(rule.Upstream)
	if upstream == "" {
		upstream = "DIRECT"
	}

	expl := MatchExplanation{
		Simulated:  true,
		Host:       strings.TrimSpace(host),
		Mode:       rule.Mode,
		Source:     ruleSource(rule),
		SiteID:     rule.SiteID,
		RuleDomain: rule.Domain,
		DNSMode:    rule.DNSMode,
		Upstream:   upstream,
		SniFake:    rule.SniFake,
		ECHEnabled: rule.ECHEnabled,
		UseCFPool:  rule.UseCFPool,
		Downgraded: downgraded,
	}

	if len(candidates) > maxExplanationCandidates {
		candidates = candidates[:maxExplanationCandidates]
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Score > candidates[j].Score })
	expl.Candidates = candidates

	switch {
	case expl.Source == "default":
		expl.Notes = append(expl.Notes, "No rule matched; the connection goes direct by default.")
	case expl.Source == "auto":
		expl.Notes = append(expl.Notes, "No manual rule matched; the auto-routing layer decided "+expl.Mode+".")
	case strings.EqualFold(expl.Mode, "block"):
		expl.Notes = append(expl.Notes, "The matched rule blocks this destination.")
	}
	if downgraded {
		expl.Notes = append(expl.Notes, "Global transparent mode downgrades the MITM rule to direct to avoid certificate errors.")
	}
	if len(candidates) > 1 {
		expl.Notes = append(expl.Notes, "Priority: exact > regex > keyword > suffix match, longer pattern wins within a class (see scores).")
	}
	if expl.DNSMode != "" {
		expl.Notes = append(expl.Notes, "DNS mode "+expl.DNSMode+" applies to this host.")
	}
	return expl
}
