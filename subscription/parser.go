package subscription

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Node is a single proxy entry parsed from a Clash subscription.
type Node struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Server     string            `json:"server"`
	Port       int               `json:"port"`
	ServerName string            `json:"server_name,omitempty"`
	UDP        bool              `json:"udp"`
	Options    map[string]string `json:"options,omitempty"`
	// Raw is the node's original Clash YAML mapping, kept verbatim so the
	// mihomo adapters (see mihomo.go) see the exact config Clash itself
	// would load — nested blocks like ws-opts/reality-opts/grpc-opts that
	// the flattened Options map cannot carry survive here.
	Raw map[string]any `json:"raw,omitempty"`
}

// Group is a Clash proxy-group.
type Group struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Members  []string `json:"members"`
	Selected string   `json:"selected,omitempty"`
}

// ParsedConfig is the normalized result of a Clash subscription payload.
type ParsedConfig struct {
	Nodes      []Node            `json:"nodes"`
	Groups     []Group           `json:"groups"`
	Rules      []string          `json:"rules"`
	RawRuleMap map[string]string `json:"-"`
}

type rawProxy struct {
	Name              string         `yaml:"name"`
	Type              string         `yaml:"type"`
	Server            string         `yaml:"server"`
	Port              int            `yaml:"port"`
	ServerName        string         `yaml:"servername"`
	SNI               string         `yaml:"sni"`
	UDP               bool           `yaml:"udp"`
	TLS               bool           `yaml:"tls"`
	SkipCert          bool           `yaml:"skip-cert-verify"`
	Password          string         `yaml:"password"`
	Username          string         `yaml:"username"`
	Cipher            string         `yaml:"cipher"`
	Method            string         `yaml:"method"`
	UUID              string         `yaml:"uuid"`
	AlterID           int            `yaml:"alterId"`
	Network           string         `yaml:"network"`
	Path              string         `yaml:"path"`
	Host              string         `yaml:"host"`
	WSPath            string         `yaml:"ws-path"`
	WSHeaders         map[string]any `yaml:"ws-headers"`
	Flow              string         `yaml:"flow"`
	ALPN              []string       `yaml:"alpn"`
	ClientFingerprint string         `yaml:"client-fingerprint"`
	// Hysteria 2
	Obfs         string `yaml:"obfs"`
	ObfsPassword string `yaml:"obfs-password"`
	Fingerprint  string `yaml:"fingerprint"` // certificate SHA-256 pin for hysteria2
	Ports        string `yaml:"ports"`
	UpMbps       int    `yaml:"up"`
	DownMbps     int    `yaml:"down"`
	// WireGuard
	PublicKey    string   `yaml:"public-key"`
	PrivateKey   string   `yaml:"private-key"`
	PreSharedKey string   `yaml:"pre-shared-key"`
	IP           string   `yaml:"ip"`
	IPv6         string   `yaml:"ipv6"`
	Reserved     any      `yaml:"reserved"`
	AllowedIPs   []string `yaml:"allowed-ips"`
}

type rawGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
	Use     []string `yaml:"use"`
	URL     string   `yaml:"url"`
}

type rawConfig struct {
	Proxies     []map[string]any `yaml:"proxies"`
	ProxyGroups []rawGroup       `yaml:"proxy-groups"`
	Rules       []string         `yaml:"rules"`
}

var knownNodeTypes = map[string]bool{
	"ss": true, "ssr": true, "vmess": true, "vless": true, "trojan": true,
	"socks5": true, "http": true, "snell": true, "hysteria": true,
	"hysteria2": true, "tuic": true, "wireguard": true, "anytls": true,
	"ssh": true, "mieru": true,
}

// ParseClash decodes a Clash YAML subscription payload.
func ParseClash(payload []byte) (*ParsedConfig, error) {
	var raw rawConfig
	if err := yaml.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("parse clash yaml: %w", err)
	}

	out := &ParsedConfig{
		Nodes:      make([]Node, 0, len(raw.Proxies)),
		Groups:     make([]Group, 0, len(raw.ProxyGroups)),
		Rules:      make([]string, 0, len(raw.Rules)),
		RawRuleMap: make(map[string]string),
	}

	seen := make(map[string]bool, len(raw.Proxies))
	for _, m := range raw.Proxies {
		b, err := yaml.Marshal(m)
		if err != nil {
			continue
		}
		var p rawProxy
		if err := yaml.Unmarshal(b, &p); err != nil {
			continue
		}
		name := strings.TrimSpace(p.Name)
		if name == "" || seen[name] {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(p.Type))
		if !knownNodeTypes[typ] {
			continue
		}
		seen[name] = true

		sni := strings.TrimSpace(p.ServerName)
		if sni == "" {
			sni = strings.TrimSpace(p.SNI)
		}

		out.Nodes = append(out.Nodes, Node{
			Name:       name,
			Type:       typ,
			Server:     strings.TrimSpace(p.Server),
			Port:       p.Port,
			ServerName: sni,
			UDP:        p.UDP,
			Options:    buildOptions(typ, p),
			Raw:        m,
		})
	}

	for _, g := range raw.ProxyGroups {
		name := strings.TrimSpace(g.Name)
		if name == "" {
			continue
		}
		members := make([]string, 0, len(g.Proxies)+len(g.Use))
		members = append(members, g.Proxies...)
		members = append(members, g.Use...)
		out.Groups = append(out.Groups, Group{
			Name:    name,
			Type:    strings.ToLower(strings.TrimSpace(g.Type)),
			Members: members,
		})
	}

	for _, r := range raw.Rules {
		trimmed := strings.TrimSpace(r)
		if trimmed == "" {
			continue
		}
		out.Rules = append(out.Rules, trimmed)
		fields := strings.SplitN(trimmed, ",", 2)
		if len(fields) == 2 {
			out.RawRuleMap[strings.TrimSpace(fields[0])] = strings.TrimSpace(fields[1])
		}
	}

	return out, nil
}

func buildOptions(typ string, p rawProxy) map[string]string {
	opts := make(map[string]string)
	put := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			opts[k] = v
		}
	}
	put("password", p.Password)
	put("username", p.Username)
	put("cipher", p.Cipher)
	put("method", p.Method)
	put("uuid", p.UUID)
	put("network", p.Network)
	put("path", firstNonEmpty(p.WSPath, p.Path))
	put("host", p.Host)
	put("flow", p.Flow)
	put("servername", firstNonEmpty(p.SNI, p.ServerName))
	if p.AlterID > 0 {
		opts["alterId"] = strconv.Itoa(p.AlterID)
	}
	if p.TLS {
		opts["tls"] = "true"
	}
	put("public-key", p.PublicKey)
	put("private-key", p.PrivateKey)
	put("pre-shared-key", p.PreSharedKey)
	put("ip", p.IP)
	put("ipv6", p.IPv6)
	if len(p.AllowedIPs) > 0 {
		put("allowed-ips", strings.Join(p.AllowedIPs, ","))
	}
	if p.Reserved != nil {
		opts["reserved"] = formatReserved(p.Reserved)
	}
	if p.SkipCert {
		opts["skip-cert-verify"] = "true"
	}
	if len(p.ALPN) > 0 {
		opts["alpn"] = strings.Join(p.ALPN, ",")
	}
	// Hysteria 2: obfs (salamander) must reach the dialer or the server drops
	// the QUIC handshake silently. The fingerprint field here is the
	// certificate SHA-256 pin, unrelated to vmess/vless client-fingerprint.
	if typ == "hysteria2" || typ == "hy2" {
		put("obfs", p.Obfs)
		put("obfs-password", p.ObfsPassword)
		put("pinSHA256", p.Fingerprint)
		put("ports", p.Ports)
	} else {
		put("client-fingerprint", p.ClientFingerprint)
	}
	if p.WSHeaders != nil {
		if v, ok := p.WSHeaders["Host"]; ok {
			put("ws-host", fmt.Sprintf("%v", v))
		}
	}
	if len(opts) == 0 {
		return nil
	}
	return opts
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// UserInfo carries the traffic quota and expiry advertised by a provider.
type UserInfo struct {
	Upload     int64 `json:"upload"`
	Download   int64 `json:"download"`
	Total      int64 `json:"total"`
	ExpireTime int64 `json:"expire_time"`
}

// Used is the consumed traffic in bytes.
func (u UserInfo) Used() int64 { return u.Upload + u.Download }

// Left is the remaining traffic in bytes; negative when the quota is unknown.
func (u UserInfo) Left() int64 {
	if u.Total <= 0 {
		return -1
	}
	left := u.Total - u.Used()
	if left < 0 {
		return 0
	}
	return left
}

// ExpireDate returns the expiry as a time value; zero when unset.
func (u UserInfo) ExpireDate() time.Time {
	if u.ExpireTime <= 0 {
		return time.Time{}
	}
	return time.Unix(u.ExpireTime, 0)
}

// ParseSubscriptionUserInfo decodes the clash subscription-userinfo header.
// The value looks like: upload=1; download=2; total=3; expire=1590000000
func ParseSubscriptionUserInfo(header string) UserInfo {
	var info UserInfo
	for _, part := range strings.Split(header, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "upload":
			info.Upload = n
		case "download":
			info.Download = n
		case "total":
			info.Total = n
		case "expire":
			// Some providers send a millisecond timestamp; Clash treats the
			// field as unix seconds, so normalize the obvious range.
			if n >= 1e12 {
				n /= 1000
			}
			info.ExpireTime = n
		}
	}
	return info
}

// formatReserved renders the WireGuard reserved field, which Clash allows
// either as a three element list or as a short string.
func formatReserved(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, fmt.Sprintf("%v", item))
		}
		return strings.Join(parts, ",")
	case []int:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, strconv.Itoa(item))
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprintf("%v", value)
	}
}
