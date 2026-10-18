package subscription

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestReviewXUDPFrameLayout(t *testing.T) {
	dest := M.Socksaddr{Fqdn: "example.com", Port: 443}
	payload := []byte("hello-xudp")
	frame := buildXUDPFrame(0x1234, xudpStatusData, dest, payload, nil)

	if len(frame) < 4 {
		t.Fatalf("frame shorter than fixed head: %d", len(frame))
	}
	if frame[0] != 0x12 || frame[1] != 0x34 {
		t.Fatalf("session id mismatch: %02x%02x", frame[0], frame[1])
	}
	if frame[2] != xudpStatusData {
		t.Fatalf("status byte = %02x, want %02x", frame[2], xudpStatusData)
	}
	if frame[3] != 0x00 {
		t.Fatalf("padding length = %d, want 0", frame[3])
	}
	if frame[4] != 0x03 {
		t.Fatalf("address type byte must immediately follow the 4-byte fixed head, got atyp=%02x", frame[4])
	}

	got, src, status, err := readXUDPFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("readXUDPFrame: %v", err)
	}
	if status != xudpStatusData {
		t.Fatalf("status = %02x", status)
	}
	if got := src.Fqdn; got != "example.com" || src.Port != 443 {
		t.Fatalf("source = %s:%d", got, src.Port)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q", got)
	}
}

func TestReviewXUDPControlFrameCarriesAddress(t *testing.T) {
	dest := M.Socksaddr{Addr: ipAddr(net.IP{10, 0, 0, 1}), Port: 9999}
	frame := buildXUDPFrame(1, xudpStatusEnd, dest, nil, nil)
	_, _, status, err := readXUDPFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("END frame with address must round-trip: %v", err)
	}
	if status != xudpStatusEnd {
		t.Fatalf("status = %02x", status)
	}
}

func TestReviewTrojanUDPLengthIncludesCRLF(t *testing.T) {
	node := Node{Name: "t", Type: "trojan", Server: "127.0.0.1", Port: 443,
		Options: map[string]string{"password": "pw"}}
	payload := []byte("DATA")
	frame, err := buildTrojanUDPHandshake(node, "example.com", 443, payload)
	if err != nil {
		t.Fatal(err)
	}
	lengthPos := len(frame) - 4 - len(payload)
	gotLen := int(frame[lengthPos])<<8 | int(frame[lengthPos+1])
	if gotLen != len(payload)+2 {
		t.Fatalf("length field = %d, want len(payload)+2 = %d", gotLen, len(payload)+2)
	}
	if frame[lengthPos+2] != 0x0d || frame[lengthPos+3] != 0x0a {
		t.Fatal("CRLF must immediately follow the length field")
	}
}

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

func TestReviewVMessAEADKeyLengths(t *testing.T) {
	uuid, err := parseUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	if err != nil {
		t.Fatal(err)
	}

	auto := chachaKey(t, func() [32]byte {
		var k [32]byte
		copy(k[:16], uuid[:])
		return k
	}())
	if auto != 12 {
		t.Fatalf("auto nonce size = %d", auto)
	}

	gcm := chachaKey(t, func() [32]byte {
		var k [32]byte
		sum := sha256.Sum256(uuid[:])
		copy(k[:16], sum[:16])
		return k
	}())
	if gcm != 12 {
		t.Fatalf("aes-128-gcm nonce size = %d", gcm)
	}

	var short [16]byte
	copy(short[:], uuid[:])
	if _, err := chacha20poly1305.New(short[:]); err == nil {
		t.Fatal("16-byte key must be rejected by chacha20poly1305.New (returns error, not panic)")
	}
}

func chachaKey(t *testing.T, k [32]byte) int {
	t.Helper()
	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}
	return aead.NonceSize()
}

func TestReviewTUICPacketSizeBelowAddrLen(t *testing.T) {
	frame := []byte{tuicVersion, tuicCmdPacket}
	frame = append(frame, 0x00, 0x01)
	frame = append(frame, 0x00, 0x01)
	frame = append(frame, 0x01, 0x00)
	frame = append(frame, 0x00, 0x03)
	frame = append(frame, tuicAddrIPv4, 10, 0, 0, 1, 0x01, 0xbb, 0xaa, 0xbb)

	didPanic := func() (p bool) {
		defer func() {
			if r := recover(); r != nil {
				p = true
			}
		}()
		payload, _, ok := parseTUICPacket(frame)
		if ok {
			t.Fatal("frame with SIZE < addrLen must be rejected")
		}
		if payload != nil {
			t.Fatal("rejected frame must not yield payload")
		}
		return false
	}()
	if didPanic {
		t.Fatal("parseTUICPacket must not panic when SIZE < addrLen")
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
