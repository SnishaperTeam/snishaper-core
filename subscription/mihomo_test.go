package subscription

import "testing"

// Raw nodes delegate protocol/UDP support to the mihomo adapters instead of
// the legacy type whitelist.
func TestRawNodeSupportDelegatesToMihomo(t *testing.T) {
	ss := Node{Name: "ss", Type: "ss", Raw: map[string]any{
		"name": "ss", "type": "ss", "server": "1.2.3.4", "port": 8388,
		"cipher": "aes-128-gcm", "password": "pw", "udp": true,
	}}
	if !ss.Supported() {
		t.Error("raw ss node should be supported")
	}
	if !ss.UDPSupported() {
		if p, err := ss.MihomoProxy(); err != nil {
			t.Errorf("ss parse failed: %v", err)
		} else {
			t.Errorf("ss with udp option carries UDP in the core (SupportUDP=%v)", p.SupportUDP())
		}
	}

	// vmess defaults to udp off in the core unless the option is set.
	vm := Node{Name: "vm", Type: "vmess", Raw: map[string]any{
		"name": "vm", "type": "vmess", "server": "1.2.3.4", "port": 443,
		"uuid":   "b831381d-6324-4d53-ad4f-8cda48b30811",
		"cipher": "auto", "alterId": 0,
	}}
	if !vm.Supported() {
		t.Error("raw vmess node should be supported")
	}
	if vm.UDPSupported() {
		t.Error("vmess without the udp option should not report UDP support")
	}

	// A protocol outside the legacy whitelist still works through the core.
	exotic := Node{Name: "ex", Type: "anytls", Raw: map[string]any{
		"name": "ex", "type": "anytls", "server": "1.2.3.4", "port": 443, "password": "pw",
	}}
	if !exotic.Supported() {
		t.Error("raw anytls node should be supported via the core")
	}
}
