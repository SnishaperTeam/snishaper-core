package proxy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/SnishaperTeam/snishaper-core/config"
)

func TestTUNConfigInterfaceConfigIgnoresRouteExcludes(t *testing.T) {
	cfg := TUNConfig{
		InterfaceName:         "Ethernet",
		ExcludeInterfaces:     []string{"Virtual*"},
		RouteExcludeAddresses: []string{"192.168.0.0/16"},
	}

	got := cfg.InterfaceConfig()

	if got.ForceInterface != "Ethernet" {
		t.Fatalf("ForceInterface must pass through, got %q", got.ForceInterface)
	}
	if len(got.ExcludeInterfaces) != 1 || got.ExcludeInterfaces[0] != "Virtual*" {
		t.Fatalf("ExcludeInterfaces must pass through, got %v", got.ExcludeInterfaces)
	}
	// route_exclude_address 是"不进 TUN 的路由"，与"不得作为出站网卡"语义不同。
	// 混用会让用户为放行内网而填的网段把唯一出口网卡直接排除掉。
	if len(got.ExcludeAddresses) != 0 {
		t.Fatalf("RouteExcludeAddresses must not feed NIC exclusion, got %v", got.ExcludeAddresses)
	}
}

func TestNormalizeTUNConfigClampsMTU(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{0, 9000},
		{-1, 9000},
		{1, 576},
		{575, 576},
		{1500, 1500},
		{9000, 9000},
		{9001, 9000},
		{65535, 9000},
	}
	for _, tc := range cases {
		got := normalizeTUNConfig(TUNConfig{MTU: tc.in}, config.Brand{}).MTU
		if got != tc.want {
			t.Fatalf("normalizeTUNConfig(MTU=%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeTUNConfigTrimsAndDeduplicates(t *testing.T) {
	cfg := normalizeTUNConfig(TUNConfig{
		InterfaceName:         "  Ethernet  ",
		ExcludeInterfaces:     []string{" a ", "a", "", "b"},
		RouteExcludeAddresses: []string{" 10.0.0.0/8 ", "10.0.0.0/8"},
	}, config.Brand{})

	if cfg.InterfaceName != "Ethernet" {
		t.Fatalf("InterfaceName must be trimmed, got %q", cfg.InterfaceName)
	}
	if len(cfg.ExcludeInterfaces) != 2 {
		t.Fatalf("ExcludeInterfaces must be trimmed and deduplicated, got %v", cfg.ExcludeInterfaces)
	}
	if len(cfg.RouteExcludeAddresses) != 1 {
		t.Fatalf("RouteExcludeAddresses must be deduplicated, got %v", cfg.RouteExcludeAddresses)
	}
}

func TestNormalizeTUNConfigDisablesStrictRoute(t *testing.T) {
	if normalizeTUNConfig(TUNConfig{StrictRoute: true}, config.Brand{}).StrictRoute {
		t.Fatal("StrictRoute must stay disabled: it blackholes traffic under Wintun")
	}
}

func TestNormalizeTUNConfigRejectsUnknownStack(t *testing.T) {
	if got := normalizeTUNConfig(TUNConfig{Stack: "bogus"}, config.Brand{}).Stack; got != "gvisor" {
		t.Fatalf("want gvisor, got %q", got)
	}
	if got := normalizeTUNConfig(TUNConfig{Stack: "mixed"}, config.Brand{}).Stack; got != "mixed" {
		t.Fatalf("want mixed, got %q", got)
	}
}

// TestNormalizeTUNConfigDefaultsAdapterName pins the adapter-name default to the
// embedder's brand: the reference product keeps "SniShaper", a branded embedder
// (FlowWeaver) must get its own name, and an explicit user value always wins.
func TestNormalizeTUNConfigDefaultsAdapterName(t *testing.T) {
	if got := normalizeTUNConfig(TUNConfig{AdapterName: "  "}, config.Brand{}).AdapterName; got != "SniShaper" {
		t.Fatalf("want SniShaper, got %q", got)
	}
	if got := normalizeTUNConfig(TUNConfig{AdapterName: "  MyTun "}, config.Brand{}).AdapterName; got != "MyTun" {
		t.Fatalf("want MyTun, got %q", got)
	}
	flowweaver := config.Brand{Name: "FlowWeaver"}
	if got := normalizeTUNConfig(TUNConfig{}, flowweaver).AdapterName; got != "FlowWeaver" {
		t.Fatalf("want FlowWeaver for a branded embedder, got %q", got)
	}
	if got := normalizeTUNConfig(TUNConfig{AdapterName: "MyTun"}, flowweaver).AdapterName; got != "MyTun" {
		t.Fatalf("explicit adapter name must win over the brand, got %q", got)
	}
}

func TestRouteExcludePrefixesClassifiesFamilies(t *testing.T) {
	cfg := TUNConfig{
		RouteExcludeAddresses: []string{
			"10.0.0.0/8",
			"fd00::/8",
			"192.168.1.1",
			"not-a-cidr",
			"",
		},
	}

	v4, v6 := cfg.RouteExcludePrefixes()

	if len(v4) != 2 {
		t.Fatalf("expected 2 IPv4 prefixes, got %v", v4)
	}
	if len(v6) != 1 {
		t.Fatalf("expected 1 IPv6 prefix, got %v", v6)
	}
	if v6[0].String() != "fd00::/8" {
		t.Fatalf("unexpected IPv6 prefix %s", v6[0])
	}
	// 裸地址应被规范化为 /32 与 /128。
	var foundHost, foundLAN bool
	for _, p := range v4 {
		if p.String() == "192.168.1.1/32" {
			foundHost = true
		}
		if p.Contains(netip.MustParseAddr("10.1.2.3")) {
			foundLAN = true
		}
	}
	if !foundHost || !foundLAN {
		t.Fatalf("unexpected IPv4 prefixes %v", v4)
	}
}

// TestWithProductNameReachesTUNAndDoH covers the embedder-facing option: a
// product name must flow into the user-visible TUN adapter default and into the
// DoH User-Agent, without any per-callsite wiring.
func TestWithProductNameReachesTUNAndDoH(t *testing.T) {
	t.Run("default keeps the reference product", func(t *testing.T) {
		p := &ProxyServer{}
		applyProxyOptions(p, []Option{})
		if got := p.brand.Display(); got != config.DefaultProductName {
			t.Fatalf("brand = %q, want %q", got, config.DefaultProductName)
		}
		if got := normalizeTUNConfig(TUNConfig{}, p.brand).AdapterName; got != config.DefaultProductName {
			t.Fatalf("adapter name = %q, want %q", got, config.DefaultProductName)
		}
		if ua := dohUserAgent(p.brand); !strings.HasSuffix(ua, config.DefaultProductName+"/1.0") {
			t.Fatalf("User-Agent = %q, want the reference product token", ua)
		}
	})

	t.Run("embedder product name wins", func(t *testing.T) {
		p := &ProxyServer{}
		applyProxyOptions(p, []Option{WithProductName("FlowWeaver")})
		if got := p.brand.Display(); got != "FlowWeaver" {
			t.Fatalf("brand = %q, want FlowWeaver", got)
		}
		if got := normalizeTUNConfig(TUNConfig{}, p.brand).AdapterName; got != "FlowWeaver" {
			t.Fatalf("adapter name = %q, want FlowWeaver", got)
		}
		ua := dohUserAgent(p.brand)
		if !strings.HasSuffix(ua, "FlowWeaver/1.0") {
			t.Fatalf("User-Agent = %q, want the FlowWeaver token", ua)
		}
		if strings.Contains(ua, config.DefaultProductName) {
			t.Fatalf("User-Agent = %q must not leak the reference product name", ua)
		}
		// The browser prefix must survive: some resolvers reject non-browser clients.
		if !strings.HasPrefix(ua, "Mozilla/5.0") {
			t.Fatalf("User-Agent = %q must keep the browser prefix", ua)
		}
	})
}

// TestWithBrandMatchesProductName checks the two option spellings agree.
func TestWithBrandMatchesProductName(t *testing.T) {
	viaBrand := &ProxyServer{}
	applyProxyOptions(viaBrand, []Option{WithBrand(config.Brand{Name: "FlowWeaver"})})

	viaName := &ProxyServer{}
	applyProxyOptions(viaName, []Option{WithProductName("FlowWeaver")})

	if viaBrand.brand != viaName.brand {
		t.Fatalf("WithBrand gave %q, WithProductName gave %q", viaBrand.brand.Display(), viaName.brand.Display())
	}
}

// TestInterfaceConfigForCarriesBrand pins the netiface handoff: the brand must
// reach the interface config so our own TUN device is never chosen as the
// outbound uplink, which would loop traffic back into the tunnel.
func TestInterfaceConfigForCarriesBrand(t *testing.T) {
	cfg := TUNConfig{InterfaceName: "Ethernet", ExcludeInterfaces: []string{"Virtual*"}}

	got := cfg.InterfaceConfigFor(config.Brand{Name: "FlowWeaver"})

	if got.Brand.Display() != "FlowWeaver" {
		t.Fatalf("InterfaceConfigFor brand = %q, want FlowWeaver", got.Brand.Display())
	}
	if got.ForceInterface != "Ethernet" {
		t.Fatalf("ForceInterface = %q, want Ethernet", got.ForceInterface)
	}
	if len(got.ExcludeInterfaces) != 1 || got.ExcludeInterfaces[0] != "Virtual*" {
		t.Fatalf("ExcludeInterfaces = %v, want [Virtual*]", got.ExcludeInterfaces)
	}
}
