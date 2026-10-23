package proxy

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SnishaperTeam/snishaper-core/cfpool"
)

func newTestProxyServer(t *testing.T) *ProxyServer {
	t.Helper()
	return NewProxyServer("127.0.0.1:0")
}

func newTestRuleManager(t *testing.T) *RuleManager {
	t.Helper()
	dir := t.TempDir()
	return NewRuleManager(filepath.Join(dir, "settings.json"), filepath.Join(dir, "rules.json"))
}

func TestUpdateIPPoolCreatesAndUpdates(t *testing.T) {
	p := newTestProxyServer(t)
	p.UpdateIPPool("cloudfront", []string{"13.226.69.219", "13.226.69.220"})

	pool := p.GetIPPool("cloudfront")
	if pool == nil {
		t.Fatal("expected named pool to be created")
	}
	if stats := pool.GetAllIPsWithStats(); len(stats) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(stats))
	}

	p.UpdateIPPool("cloudfront", []string{"13.226.69.221"})
	if stats := p.GetIPPoolStats("cloudfront"); len(stats) != 1 {
		t.Fatalf("expected pool update to replace IPs, got %d", len(stats))
	}
}

func TestUpdateIPPoolIgnoresInvalidInput(t *testing.T) {
	p := newTestProxyServer(t)
	p.UpdateIPPool("", []string{"1.1.1.1"})
	p.UpdateIPPool("  ", []string{"1.1.1.1"})
	p.UpdateIPPool("cloudflare", []string{"1.1.1.1"}) // reserved for the legacy pool
	p.UpdateIPPool("empty-ips", nil)
	if names := p.IPPoolNames(); len(names) != 0 {
		t.Fatalf("expected no pools, got %v", names)
	}
}

func TestPoolForRuleResolution(t *testing.T) {
	p := newTestProxyServer(t)
	p.UpdateIPPool("cloudfront", []string{"13.226.69.219"})

	if got := p.poolForRule(Rule{IPPool: "cloudfront"}); got == nil {
		t.Fatal("named pool rule should resolve to the pool")
	}
	if got := p.poolForRule(Rule{IPPool: " CloudFront "}); got == nil {
		t.Fatal("pool name lookup should trim and lowercase")
	}
	if got := p.poolForRule(Rule{IPPool: "missing"}); got != nil {
		t.Fatal("unknown pool name should resolve to nil (DNS fallback)")
	}

	p.UpdateCloudflareIPPool([]string{"104.16.1.1"})
	if got := p.poolForRule(Rule{UseCFPool: true}); got == nil {
		t.Fatal("legacy use_cf_pool rule should resolve to the Cloudflare pool")
	}
	if got := p.poolForRule(Rule{IPPool: "cloudfront", UseCFPool: true}); got == nil {
		t.Fatal("explicit ip_pool should take precedence over use_cf_pool")
	}
	if got := p.poolForRule(Rule{}); got != nil {
		t.Fatal("rule without pool flags should resolve to nil")
	}
}

func TestIPPoolUsableRequiresIPs(t *testing.T) {
	p := newTestProxyServer(t)
	if p.IPPoolUsable("cloudfront") {
		t.Fatal("missing pool must not be usable")
	}
	p.UpdateIPPool("cloudfront", []string{"13.226.69.219"})
	if !p.IPPoolUsable("cloudfront") {
		t.Fatal("fresh pool with IPs should be usable")
	}
	// A pool fetched more than a day ago is stale and must not serve dials.
	pool := p.GetIPPool("cloudfront")
	pool.SetLastFetchTime(time.Now().AddDate(0, 0, -2))
	if p.IPPoolUsable("cloudfront") {
		t.Fatal("stale pool must not be usable")
	}
}

func TestRemoveIPPool(t *testing.T) {
	p := newTestProxyServer(t)
	p.UpdateIPPool("custom", []string{"1.2.3.4"})
	p.RemoveIPPool("custom")
	if p.GetIPPool("custom") != nil {
		t.Fatal("pool should be removed")
	}
	if got := p.poolForRule(Rule{IPPool: "custom"}); got != nil {
		t.Fatal("rules of a removed pool should fall back to nil")
	}
	p.RemoveIPPool("custom") // idempotent
}

func TestNormalizeIPPoolConfigs(t *testing.T) {
	got := normalizeIPPoolConfigs([]IPPoolConfig{
		{Name: "  CloudFront ", PreferredIPs: []string{" 1.1.1.1 ", "", " 2.2.2.2 "}},
		{Name: "cloudfront", PreferredIPs: []string{"3.3.3.3"}}, // duplicate after lowercasing
		{Name: "cloudflare", PreferredIPs: []string{"4.4.4.4"}}, // reserved
		{Name: "", PreferredIPs: []string{"5.5.5.5"}},           // no name
		{Name: " gcore ", PreferredIPs: []string{"6.6.6.6"}},
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 pools, got %d: %+v", len(got), got)
	}
	if got[0].Name != "cloudfront" || len(got[0].PreferredIPs) != 2 {
		t.Fatalf("unexpected first pool: %+v", got[0])
	}
	if got[1].Name != "gcore" {
		t.Fatalf("unexpected second pool: %+v", got[1])
	}
}

func TestIPPoolsConfigRoundTrip(t *testing.T) {
	p := newTestProxyServer(t)
	_ = p
	rm := newTestRuleManager(t)
	err := rm.UpdateIPPoolsConfig([]IPPoolConfig{{Name: "CloudFront", PreferredIPs: []string{"13.226.69.219"}}})
	if err != nil {
		t.Fatalf("UpdateIPPoolsConfig: %v", err)
	}
	pools := rm.GetIPPoolsConfig()
	if len(pools) != 1 || pools[0].Name != "cloudfront" || len(pools[0].PreferredIPs) != 1 {
		t.Fatalf("unexpected persisted pools: %+v", pools)
	}
}

func TestFetchCDNIPsRejectsUnknownCDN(t *testing.T) {
	_, err := cfpool.FetchCDNIPs("gcore", "")
	if err == nil || !strings.Contains(err.Error(), "gcore") {
		t.Fatalf("expected unknown-CDN error, got %v", err)
	}
	if _, ok := cfpool.CDNFetchEndpoints["cloudflare"]; !ok {
		t.Fatal("cloudflare endpoint must stay registered")
	}
	if _, ok := cfpool.CDNFetchEndpoints["cloudfront"]; !ok {
		t.Fatal("cloudfront endpoint must be registered")
	}
}
