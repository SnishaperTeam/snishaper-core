package subscription

import (
	"strings"
)

// SiteGroup mirrors proxy.SiteGroup without importing the proxy package,
// keeping this package free of a dependency cycle.
type SiteGroup struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Mode       string   `json:"mode"`
	DNSMode    string   `json:"dns_mode,omitempty"`
	SniFake    string   `json:"sni_fake,omitempty"`
	Domains    []string `json:"domains"`
	ECHEnabled bool     `json:"ech_enabled"`
	UseCFPool  bool     `json:"use_cf_pool"`
	CertVerify struct {
		Mode  string   `json:"mode"`
		Names []string `json:"names,omitempty"`
	} `json:"cert_verify"`
	Website  string `json:"website,omitempty"`
	Enabled  bool   `json:"enabled"`
	Upstream string `json:"upstream,omitempty"`
}

// ruleTargetDirect marks a Clash target that means "no proxy".
const ruleTargetDirect = "DIRECT"

// catchAllDomain is the pseudo-domain used for MATCH/FINAL rules. domainMatchScore
// treats a "~" prefix as a regex; this pattern matches any non-empty host and
// scores 900+2, below every concrete domain rule (1000+ for exact matches), so it
// only applies when nothing more specific matched.
const catchAllDomain = "~.+"

type ruleAggregate struct {
	domains   []string
	proxied   bool
	direct    bool
	reject    bool
	sniFake   string
	onlyGroup string
}

// ConvertRules maps Clash rule lines into site groups.
//
// Clash targets (a proxy group name, DIRECT, REJECT) are intentionally not
// bound to a concrete node here: node selection happens in the UI, and the
// proxy layer resolves the group name at dial time.
func ConvertRules(cfg *ParsedConfig) []SiteGroup {
	if cfg == nil {
		return nil
	}

	aggregates := make(map[string]*ruleAggregate)
	var order []string

	for _, raw := range cfg.Rules {
		// "MATCH,<target>" has two fields; domain rules have three.
		// Using SplitN(...,3) would leave target empty for the two-field form.
		fields := strings.Split(raw, ",")
		if len(fields) < 2 {
			continue
		}

		ruleType := strings.ToUpper(strings.TrimSpace(fields[0]))
		payload := strings.TrimSpace(fields[1])
		target := ""
		if len(fields) >= 3 {
			target = strings.TrimSpace(strings.Join(fields[2:], ","))
		} else if ruleType == "MATCH" || ruleType == "FINAL" {
			// Two-field form: "MATCH,Proxy" — the only value is the target.
			target = payload
			payload = ""
		}

		domains, ok := extractDomains(ruleType, payload)
		if !ok || len(domains) == 0 {
			continue
		}

		key := target
		agg, exists := aggregates[key]
		if !exists {
			agg = &ruleAggregate{}
			aggregates[key] = agg
			order = append(order, key)
		}

		agg.domains = append(agg.domains, domains...)
		agg.onlyGroup = target

		switch {
		case strings.EqualFold(target, ruleTargetDirect):
			agg.direct = true
		case strings.EqualFold(target, "REJECT"), strings.EqualFold(target, "REJECT-DROP"):
			agg.reject = true
		case strings.EqualFold(target, "PASS"), strings.EqualFold(target, "COMPATIBLE"):
			// fall through to proxied
			agg.proxied = true
		default:
			agg.proxied = true
		}

		if opts := parseRuleOptions(fields); opts != "" {
			agg.sniFake = opts
		}
	}

	groups := make([]SiteGroup, 0, len(order))
	matchKey := ""
	for _, target := range order {
		agg := aggregates[target]
		if len(agg.domains) == 0 {
			continue
		}

		// MATCH/FINAL are catch-all rules: they must merge into the group
		// they target, otherwise the fallback never applies to any domain.
		if hasWildcard(agg.domains) {
			if matchKey != "" {
				continue
			}
			matchKey = target
		}

		mode := "direct"
		switch {
		case agg.proxied:
			mode = "mitm"
		case agg.reject:
			mode = "direct"
		}

		name := target
		if name == "" {
			name = ruleTargetDirect
		}
		id := "sub-" + sanitizeID(target)

		if agg.proxied {
			agg.domains = dedupeDomains(agg.domains)
		} else {
			// A DIRECT catch-all is kept: it scores below every concrete
			// domain rule, so it only routes what nothing else matched while
			// preserving the subscription's MATCH,DIRECT semantics.
			agg.domains = dedupeDomains(agg.domains)
		}

		sg := SiteGroup{
			ID:      id,
			Name:    name,
			Mode:    mode,
			Domains: agg.domains,
			Enabled: true,
		}
		if agg.sniFake != "" {
			sg.SniFake = agg.sniFake
		}
		sg.CertVerify.Mode = "strict_real"

		// Merge catch-all domains into an already emitted group with the
		// same target so the fallback is preserved.
		if matchKey == target {
			if existing, ok := findGroup(groups, id); ok {
				existing.Domains = dedupeDomains(append(existing.Domains, agg.domains...))
				continue
			}
		}
		groups = append(groups, sg)
	}

	return groups
}

func findGroup(groups []SiteGroup, id string) (*SiteGroup, bool) {
	for i := range groups {
		if groups[i].ID == id {
			return &groups[i], true
		}
	}
	return nil, false
}

func hasWildcard(domains []string) bool {
	for _, d := range domains {
		if d == catchAllDomain || d == "*" {
			return true
		}
	}
	return false
}

func extractDomains(ruleType, payload string) ([]string, bool) {
	switch ruleType {
	case "DOMAIN":
		if payload == "" {
			return nil, false
		}
		return []string{payload}, true
	case "DOMAIN-SUFFIX":
		if payload == "" {
			return nil, false
		}
		return []string{payload}, true
	case "DOMAIN-KEYWORD":
		if payload == "" {
			return nil, false
		}
		return []string{"*" + payload + "*"}, true
	case "DOMAIN-REGEX":
		if payload == "" {
			return nil, false
		}
		return []string{payload}, true
	case "GEOSITE":
		return []string{"geosite:" + payload}, true
	case "MATCH", "FINAL":
		// A literal "*" never matches: domainMatchScore only understands
		// "~regex" for wildcards. This anchored pattern scores below any
		// concrete domain, which is exactly catch-all precedence.
		return []string{catchAllDomain}, true
	default:
		return nil, false
	}
}

func parseRuleOptions(fields []string) string {
	for _, f := range fields[1:] {
		f = strings.TrimSpace(f)
		if strings.HasPrefix(strings.ToLower(f), "sni=") {
			return strings.TrimSpace(f[4:])
		}
	}
	return ""
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "group"
	}
	return out
}

func dedupeDomains(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.TrimSpace(d)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}
