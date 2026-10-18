package subscription

import "testing"

const sampleClash = `
proxies:
  - name: "HK-01"
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-256-gcm
    password: "secret"
    udp: true
  - name: "JP-Trojan"
    type: trojan
    server: jp.example.com
    port: 443
    password: "pw"
    sni: jp.example.com
    skip-cert-verify: true
  - name: "US-VMess"
    type: vmess
    server: us.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-path: /ray
    ws-headers:
      Host: us.example.com
  - name: "Direct-Socks"
    type: socks5
    server: 127.0.0.1
    port: 1080

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - HK-01
      - JP-Trojan
      - US-VMess
  - name: Auto
    type: url-test
    proxies:
      - HK-01
      - US-VMess
    url: http://www.gstatic.com/generate_204
    interval: 300

rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN-SUFFIX,youtube.com,Proxy
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN,example.org,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
`

func TestParseClash(t *testing.T) {
	cfg, err := ParseClash([]byte(sampleClash))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(cfg.Nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(cfg.Nodes))
	}

	byName := make(map[string]Node)
	for _, n := range cfg.Nodes {
		byName[n.Name] = n
	}

	ss, ok := byName["HK-01"]
	if !ok {
		t.Fatal("missing HK-01")
	}
	if ss.Type != "ss" || ss.Port != 8388 || !ss.UDP {
		t.Errorf("HK-01 parsed wrong: %+v", ss)
	}
	if ss.Options["cipher"] != "aes-256-gcm" || ss.Options["password"] != "secret" {
		t.Errorf("HK-01 options wrong: %+v", ss.Options)
	}

	trojan := byName["JP-Trojan"]
	if trojan.Options["servername"] != "jp.example.com" {
		t.Errorf("trojan sni not normalized: %+v", trojan.Options)
	}
	if trojan.Options["skip-cert-verify"] != "true" {
		t.Errorf("trojan skip-cert-verify missing: %+v", trojan.Options)
	}

	vmess := byName["US-VMess"]
	if vmess.Options["tls"] != "true" || vmess.Options["network"] != "ws" {
		t.Errorf("vmess tls/network missing: %+v", vmess.Options)
	}
	if vmess.Options["path"] != "/ray" {
		t.Errorf("vmess ws-path not captured: %+v", vmess.Options)
	}

	if len(cfg.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(cfg.Groups))
	}
	if cfg.Groups[0].Name != "Proxy" || len(cfg.Groups[0].Members) != 3 {
		t.Errorf("group Proxy wrong: %+v", cfg.Groups[0])
	}

	if len(cfg.Rules) != 6 {
		t.Fatalf("expected 6 rules, got %d", len(cfg.Rules))
	}
}

func TestConvertRules(t *testing.T) {
	cfg, err := ParseClash([]byte(sampleClash))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	groups := ConvertRules(cfg)
	if len(groups) != 2 {
		t.Fatalf("expected 2 site groups (Proxy incl. MATCH, DIRECT), got %d: %+v", len(groups), groups)
	}

	byID := make(map[string]SiteGroup)
	for _, g := range groups {
		byID[g.ID] = g
	}

	proxyGroup, ok := byID["sub-Proxy"]
	if !ok {
		t.Fatalf("Proxy group missing, got ids: %+v", byID)
	}
	if proxyGroup.Mode != "mitm" {
		t.Errorf("proxied group should map to mitm, got %q", proxyGroup.Mode)
	}
	if len(proxyGroup.Domains) != 3 {
		t.Errorf("expected google, youtube + catch-all, got %v", proxyGroup.Domains)
	}
	if countOcc(proxyGroup.Domains, "google.com") != 1 {
		t.Errorf("duplicate domain not deduped: %v", proxyGroup.Domains)
	}
	if !hasWildcard(proxyGroup.Domains) {
		t.Errorf("MATCH rule did not merge into Proxy group: %v", proxyGroup.Domains)
	}

	directGroup, ok := byID["sub-DIRECT"]
	if !ok {
		t.Fatal("DIRECT group missing")
	}
	if directGroup.Mode != "direct" {
		t.Errorf("DIRECT group should be direct mode, got %q", directGroup.Mode)
	}
	if len(directGroup.Domains) != 1 || directGroup.Domains[0] != "example.org" {
		t.Errorf("DIRECT domains wrong: %v", directGroup.Domains)
	}
}

func countOcc(list []string, v string) int {
	n := 0
	for _, x := range list {
		if x == v {
			n++
		}
	}
	return n
}

func TestParseSubscriptionUserInfo(t *testing.T) {
	info := ParseSubscriptionUserInfo("upload=1024; download=2048; total=1048576; expire=1893456000")

	if info.Used() != 3072 {
		t.Errorf("used = %d, want 3072", info.Used())
	}
	if info.Left() != 1048576-3072 {
		t.Errorf("left = %d, want %d", info.Left(), 1048576-3072)
	}
	if info.ExpireTime != 1893456000 {
		t.Errorf("expire = %d", info.ExpireTime)
	}
	if info.ExpireDate().IsZero() {
		t.Error("expire date should not be zero")
	}
}

func TestUserInfoUnknownTotal(t *testing.T) {
	info := ParseSubscriptionUserInfo("upload=1; download=2")
	if info.Left() != -1 {
		t.Errorf("unknown total should yield -1, got %d", info.Left())
	}
}

func TestParseClashInvalid(t *testing.T) {
	if _, err := ParseClash([]byte("this: is: not: valid: yaml:\n\tbroken")); err == nil {
		t.Error("expected error for malformed yaml")
	}
}
