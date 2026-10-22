package subscription

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestReviewWireguardKeyHexPriority(t *testing.T) {
	out, err := wireguardKeyToHex("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if out != "0123456789abcdef" {
		t.Fatalf("pure hex input must be returned as-is, got %q", out)
	}

	raw, _ := hex.DecodeString(strings.Repeat("ab", 16))
	b64 := base64.StdEncoding.EncodeToString(raw)
	out, err = wireguardKeyToHex(b64)
	if err != nil {
		t.Fatal(err)
	}
	if out != strings.Repeat("ab", 16) {
		t.Fatalf("base64 input must convert to hex, got %q", out)
	}

	if _, err := wireguardKeyToHex("not valid @@@"); err == nil {
		t.Fatal("invalid input must error")
	}
}

func TestReviewWireguardReservedBrackets(t *testing.T) {
	got, err := parseWireguardReserved("[209,98,59]")
	if err != nil {
		t.Fatal(err)
	}
	if got != [3]byte{209, 98, 59} {
		t.Fatalf("reserved = %v", got)
	}
}

func TestReviewCatchAllDomainMergesIntoTargetGroup(t *testing.T) {
	cfg := &ParsedConfig{
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,VPN",
			"MATCH,VPN",
		},
	}
	groups := ConvertRules(cfg)
	found := false
	for _, g := range groups {
		for _, d := range g.Domains {
			if d == catchAllDomain && g.Name == "VPN" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("catch-all must land in the target group, got %+v", groups)
	}
}

func TestReviewMatchDirectCatchAllKept(t *testing.T) {
	cfg := &ParsedConfig{
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,VPN",
			"MATCH,DIRECT",
		},
	}
	groups := ConvertRules(cfg)
	found := false
	for _, g := range groups {
		if g.Mode != "direct" {
			continue
		}
		for _, d := range g.Domains {
			if d == catchAllDomain {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("MATCH,DIRECT catch-all must survive conversion, got %+v", groups)
	}
}

func TestReviewRejectMapsToBlock(t *testing.T) {
	cfg := &ParsedConfig{
		Rules: []string{
			"DOMAIN-SUFFIX,ads.com,REJECT",
			"DOMAIN-SUFFIX,google.com,VPN",
		},
	}
	groups := ConvertRules(cfg)
	var reject *SiteGroup
	for i := range groups {
		if groups[i].Name == "REJECT" {
			reject = &groups[i]
		}
	}
	if reject == nil {
		t.Fatalf("REJECT group missing: %+v", groups)
	}
	if reject.Mode != "block" {
		t.Fatalf("REJECT must map to mode %q, got %q", "block", reject.Mode)
	}
}
