package subscription

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Clash hands out base64 keys while the UAPI interface expects hex, which is
// the single most common reason a WireGuard node fails to come up.
func TestWireguardKeyToHex(t *testing.T) {
	raw := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	b64 := base64.StdEncoding.EncodeToString(raw)
	want := "0123456789abcdef"

	if got, err := wireguardKeyToHex(b64); err != nil || got != want {
		t.Errorf("base64 key = %q (err %v), want %q", got, err, want)
	}

	// A key already in hex must pass through untouched.
	if got, err := wireguardKeyToHex(want); err != nil || got != want {
		t.Errorf("hex key = %q (err %v), want %q", got, err, want)
	}

	if got, err := wireguardKeyToHex("  "); err != nil || got != "" {
		t.Errorf("empty key = %q (err %v), want empty", got, err)
	}

	if _, err := wireguardKeyToHex("not base64 !!!"); err == nil {
		t.Error("expected an error for a malformed key")
	}
}

func TestWireguardLocalPrefixes(t *testing.T) {
	// A bare address gets the host prefix added.
	prefixes, err := wireguardLocalPrefixes("172.16.0.2", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(prefixes) != 1 || prefixes[0].String() != "172.16.0.2/32" {
		t.Errorf("prefixes = %v, want 172.16.0.2/32", prefixes)
	}

	// Both families may be declared at once.
	prefixes, err = wireguardLocalPrefixes("10.0.0.2/24", "fd00::2/64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(prefixes) != 2 {
		t.Errorf("prefixes = %v, want two entries", prefixes)
	}

	// A node without any tunnel address cannot work.
	if _, err := wireguardLocalPrefixes("", ""); err == nil {
		t.Error("expected an error when no local address is declared")
	}
	if _, err := wireguardLocalPrefixes("not-an-ip", ""); err == nil {
		t.Error("expected an error for a malformed address")
	}
}

func TestWireguardReservedForms(t *testing.T) {
	// Clash accepts a three element list.
	got, err := parseWireguardReserved("[209,98,59]")
	if err != nil {
		t.Fatalf("list form: %v", err)
	}
	if got != [3]byte{209, 98, 59} {
		t.Errorf("list form = %v, want [209 98 59]", got)
	}

	// And a short string, one byte per character.
	got, err = parseWireguardReserved("U4An")
	if err != nil {
		t.Fatalf("string form: %v", err)
	}
	if got != [3]byte{'U', '4', 'A'} {
		t.Errorf("string form = %v, want the first three characters", got)
	}

	// An absent value simply leaves the reserved field zeroed.
	got, err = parseWireguardReserved("")
	if err != nil {
		t.Fatalf("empty form: %v", err)
	}
	if got != [3]byte{} {
		t.Errorf("empty form = %v, want zeros", got)
	}

	// A list entry that is not a number must be reported.
	if _, err := parseWireguardReserved("1,two,3"); err == nil {
		t.Error("expected an error for a non numeric reserved entry")
	}
}

func TestParseWireguardConfig(t *testing.T) {
	priv := base64.StdEncoding.EncodeToString([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	pub := base64.StdEncoding.EncodeToString([]byte{0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00})

	node := Node{
		Name: "wg-node", Type: "wireguard",
		Server: "wg.example.com", Port: 51820,
		Options: map[string]string{
			"private-key": priv,
			"public-key":  pub,
			"ip":          "172.16.0.2",
			"reserved":    "[1,2,3]",
			"mtu":         "1280",
		},
	}

	cfg, err := parseWireguardConfig(node)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Keys must arrive at the UAPI stage in hex.
	if cfg.privateKey != "1122334455667788" {
		t.Errorf("private key = %q, want hex", cfg.privateKey)
	}
	if cfg.publicKey != "99aabbccddeeff00" {
		t.Errorf("public key = %q, want hex", cfg.publicKey)
	}
	if cfg.reserved != [3]byte{1, 2, 3} {
		t.Errorf("reserved = %v, want [1 2 3]", cfg.reserved)
	}
	if cfg.mtu != 1280 {
		t.Errorf("mtu = %d, want 1280", cfg.mtu)
	}
	// Without allowed-ips a single peer node routes everything.
	if len(cfg.allowedIPs) != 1 || cfg.allowedIPs[0] != "0.0.0.0/0" {
		t.Errorf("allowed ips = %v, want a default route", cfg.allowedIPs)
	}
}

func TestParseWireguardConfigRejectsIncompleteNodes(t *testing.T) {
	base := Node{
		Name: "wg", Type: "wireguard",
		Server: "wg.example.com", Port: 51820,
		Options: map[string]string{
			"private-key": base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"public-key":  base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"ip":          "172.16.0.2",
		},
	}

	// A node without an ip cannot be routed.
	noIP := base
	noIP.Options = map[string]string{
		"private-key": base.Options["private-key"],
		"public-key":  base.Options["public-key"],
	}
	if _, err := parseWireguardConfig(noIP); err == nil {
		t.Error("expected an error when the tunnel address is missing")
	}

	// A node without keys cannot authenticate.
	noKey := base
	noKey.Options = map[string]string{"ip": "172.16.0.2"}
	if _, err := parseWireguardConfig(noKey); err == nil {
		t.Error("expected an error when the keys are missing")
	}

	// A node without an endpoint has nothing to connect to.
	noServer := base
	noServer.Server = ""
	noServer.Port = 0
	if _, err := parseWireguardConfig(noServer); err == nil {
		t.Error("expected an error when the endpoint is missing")
	}
}

func TestWireguardSupported(t *testing.T) {
	if !(Node{Type: "wireguard"}).Supported() {
		t.Error("wireguard should be reported as supported")
	}
	if !(Node{Type: "wireguard"}).UDPSupported() {
		t.Error("wireguard carries udp as well")
	}
}

func TestWireguardPoolKeyDistinguishesNodes(t *testing.T) {
	a := Node{Name: "n", Type: "wireguard", Server: "a.example", Port: 1,
		Options: map[string]string{"private-key": "aa", "ip": "10.0.0.2/32"}}
	b := Node{Name: "n", Type: "wireguard", Server: "b.example", Port: 1,
		Options: map[string]string{"private-key": "aa", "ip": "10.0.0.2/32"}}

	if wireguardPoolKey(a) == wireguardPoolKey(b) {
		t.Error("nodes with different endpoints must not share a tunnel")
	}
	if wireguardPoolKey(a) != wireguardPoolKey(a) {
		t.Error("the pool key must be stable for the same node")
	}
	if !strings.Contains(wireguardPoolKey(a), "a.example") {
		t.Error("the pool key should record the endpoint")
	}
}
