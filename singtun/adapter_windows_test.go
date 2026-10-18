//go:build windows

package singtun

import (
	"testing"

	"github.com/SnishaperTeam/snishaper-core/config"
)

// TestMatchesBrandAdapterNeverClaimsForeignDevices is the safety net for stale
// adapter cleanup: it runs `SetupDiCallClassInstaller(DIF_REMOVE)` on every
// device it accepts, so a false positive silently destroys another proxy's
// network interface.
//
// The dangerous case is the shared driver name. sing-box and mihomo install the
// same Wintun driver, so their description also contains "sing-tun"/"wintun";
// only the product-specific friendly name may decide the outcome.
func TestMatchesBrandAdapterNeverClaimsForeignDevices(t *testing.T) {
	flowweaver := config.Brand{Name: "FlowWeaver"}
	snishaper := config.Brand{}

	foreign := []struct{ desc, friendly string }{
		// sing-box / mihomo share the Wintun driver: must never be claimed.
		{"Wintun Userspace Tunnel", "sing-tun"},
		{"sing-tun Tunnel", "sing-tun"},
		{"Wintun Userspace Tunnel", "sing-box"},
		{"Wintun Userspace Tunnel", "Meta"},
		{"Wintun Userspace Tunnel", "mihomo"},
		{"Wintun Userspace Tunnel", ""},
		{"Realtek PCIe GbE Family Controller", "Ethernet"},
		{"Intel(R) Wi-Fi 6 AX201 160MHz", "WLAN"},
		{"Wintun Userspace Tunnel", "Tundra"},
	}
	for _, dev := range foreign {
		if matchesBrandAdapter(snishaper, dev.desc, dev.friendly) {
			t.Errorf("SniShaper claimed foreign device desc=%q friendly=%q", dev.desc, dev.friendly)
		}
		if matchesBrandAdapter(flowweaver, dev.desc, dev.friendly) {
			t.Errorf("FlowWeaver claimed foreign device desc=%q friendly=%q", dev.desc, dev.friendly)
		}
	}
}

// TestMatchesBrandAdapterClaimsOwnDevices pins the positive cases: each product
// must still clean up its own leftovers, including the dashed and numbered
// adapter names Wintun produces.
func TestMatchesBrandAdapterClaimsOwnDevices(t *testing.T) {
	flowweaver := config.Brand{Name: "FlowWeaver"}

	own := []struct{ desc, friendly string }{
		{"FlowWeaver", "FlowWeaver"},
		{"flowweaver", "flowweaver"},
		{"Wintun Userspace Tunnel", "FlowWeaver"},
		{"Wintun Userspace Tunnel", "flow-weaver"},
		{"FlowWeaver Virtual Adapter", ""},
	}
	for _, dev := range own {
		if !matchesBrandAdapter(flowweaver, dev.desc, dev.friendly) {
			t.Errorf("FlowWeaver missed own device desc=%q friendly=%q", dev.desc, dev.friendly)
		}
	}

	// The reference product keeps working after the brand refactor.
	snishaperOwn := []struct{ desc, friendly string }{
		{"SniShaper", "SniShaper"},
		{"snishaper", "snishaper"},
		{"Wintun Userspace Tunnel", "SniShaper"},
		{"SniShaper Virtual Adapter", ""},
	}
	for _, dev := range snishaperOwn {
		if !matchesBrandAdapter(config.Brand{}, dev.desc, dev.friendly) {
			t.Errorf("SniShaper missed own device desc=%q friendly=%q", dev.desc, dev.friendly)
		}
	}
}

// TestBrandsDoNotClaimEachOther ensures the two products stay disjoint: running
// both must not let either one delete the other's adapter.
func TestBrandsDoNotClaimEachOther(t *testing.T) {
	flowweaver := config.Brand{Name: "FlowWeaver"}
	snishaper := config.Brand{}

	if matchesBrandAdapter(flowweaver, "SniShaper", "SniShaper") {
		t.Error("FlowWeaver claimed the SniShaper adapter")
	}
	if matchesBrandAdapter(snishaper, "FlowWeaver", "FlowWeaver") {
		t.Error("SniShaper claimed the FlowWeaver adapter")
	}
}
