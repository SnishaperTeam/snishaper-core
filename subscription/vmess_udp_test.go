package subscription

import (
	"bytes"
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// TestXUDPFrameRoundTrip checks the XUDP packet layout described by the
// compatibility notes:
//
//	[2 session][1 status][1 padding len][address][2 payload len][payload][padding]
func TestXUDPFrameRoundTrip(t *testing.T) {
	cases := []M.Socksaddr{
		{Fqdn: "target.test", Port: 443},
		{Addr: ipAddr(net.IPv4(1, 2, 3, 4)), Port: 80},
	}

	for _, dest := range cases {
		payload := []byte("vmess-xudp")
		padding := []byte{0xAA, 0xBB}

		frame := buildXUDPFrame(0x1234, xudpStatusData|xudpStatusNew, dest, payload, padding)

		// The fixed part is 5 bytes: session(2) status(1) padding length(1).
		if int(frame[0]) != 0x12 || int(frame[1]) != 0x34 {
			t.Errorf("%s: session id = % x, want 12 34", dest, frame[:2])
		}
		if frame[3] != byte(len(padding)) {
			t.Errorf("%s: padding length = %d, want %d", dest, frame[3], len(padding))
		}
		if frame[2]&xudpStatusData == 0 {
			t.Errorf("%s: the data flag must be set", dest)
		}

		// Decode it back.
		got, source, status, err := readXUDPFrame(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("%s: decode: %v", dest, err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("%s: payload = %q, want %q", dest, got, payload)
		}
		if status&xudpStatusData == 0 {
			t.Errorf("%s: status lost the data flag", dest)
		}
		if source.Port != dest.Port {
			t.Errorf("%s: port = %d, want %d", dest, source.Port, dest.Port)
		}
		if dest.IsDomain() && source.Fqdn != dest.Fqdn {
			t.Errorf("domain = %q, want %q", source.Fqdn, dest.Fqdn)
		}
		if !dest.IsDomain() && source.Addr.String() != dest.Addr.String() {
			t.Errorf("address = %s, want %s", source.Addr, dest.Addr)
		}
	}
}

func TestXUDPFrameWithoutPadding(t *testing.T) {
	dest := M.Socksaddr{Fqdn: "a.test", Port: 53}
	frame := buildXUDPFrame(1, xudpStatusData, dest, []byte("x"), nil)

	got, _, _, err := readXUDPFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != "x" {
		t.Errorf("payload = %q, want %q", got, "x")
	}
}

func TestXUDPEndStatus(t *testing.T) {
	// A frame that only announces the end of the session carries no payload
	// but keeps a well formed address so the layout stays positional.
	dest := M.Socksaddr{Fqdn: "a.test", Port: 53}
	frame := buildXUDPFrame(7, xudpStatusEnd, dest, nil, nil)

	payload, _, status, err := readXUDPFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload) != 0 {
		t.Errorf("an end frame should carry no payload, got %q", payload)
	}
	if status&xudpStatusEnd == 0 {
		t.Error("the end flag must survive the round trip")
	}
}

func TestXUDPRejectsTruncatedFrames(t *testing.T) {
	full := buildXUDPFrame(1, xudpStatusData,
		M.Socksaddr{Fqdn: "target.test", Port: 443}, []byte("payload"), nil)

	// Every strict prefix must fail rather than decode into garbage.
	for cut := 1; cut < len(full); cut++ {
		if _, _, _, err := readXUDPFrame(bytes.NewReader(full[:cut])); err == nil {
			t.Errorf("truncating to %d bytes should fail", cut)
		}
	}
}

func TestXUDPRejectsUnknownAddressType(t *testing.T) {
	// session(2) status(1) paddingLen(1) then an unsupported address type.
	frame := []byte{0x00, 0x01, xudpStatusData, 0x00, 0x09, 0x00, 0x00}
	if _, _, _, err := readXUDPFrame(bytes.NewReader(frame)); err == nil {
		t.Error("an unknown address type must be rejected")
	}
}

func TestVMessUDPSupported(t *testing.T) {
	if !(Node{Type: "vmess"}).UDPSupported() {
		t.Error("vmess should report udp support now")
	}
}

func TestVMessUDPRequiresUUID(t *testing.T) {
	node := Node{Name: "v", Type: "vmess", Server: "127.0.0.1", Port: 1, Options: map[string]string{}}
	if _, err := dialVMessUDP(node); err == nil {
		t.Error("expected an error when the uuid is missing")
	}

	noPort := Node{
		Name: "v", Type: "vmess", Server: "127.0.0.1",
		Options: map[string]string{"uuid": testVMessUUID},
	}
	if _, err := dialVMessUDP(noPort); err == nil {
		t.Error("expected an error when the server port is missing")
	}

	badSecurity := Node{
		Name: "v", Type: "vmess", Server: "127.0.0.1", Port: 1,
		Options: map[string]string{"uuid": testVMessUUID, "method": "aes-256-cfb"},
	}
	if _, err := dialVMessUDP(badSecurity); err == nil {
		t.Error("expected an error for an unsupported security")
	}
}

func TestVMessUDPMagicDomain(t *testing.T) {
	if xudpMagicDomain != "sp.packet-addr.v2fly.arpa" {
		t.Errorf("magic domain = %q, which the server will not recognise", xudpMagicDomain)
	}
}
