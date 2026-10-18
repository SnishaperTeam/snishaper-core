package subscription

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// TestTUICAddrEncoding locks the address layout from the v5 specification:
//
//	0x00 domain (length byte) | 0x01 IPv4 | 0x02 IPv6 | 0xff none
//	followed by a 2 byte big endian port
func TestTUICAddrEncoding(t *testing.T) {
	cases := []struct {
		host string
		port int
		typ  byte
	}{
		{"example.com", 443, tuicAddrDomain},
		{"1.2.3.4", 80, tuicAddrIPv4},
		{"2001:db8::1", 53, tuicAddrIPv6},
	}

	for _, c := range cases {
		encoded, err := encodeTUICAddr(c.host, c.port)
		if err != nil {
			t.Fatalf("encode %s: %v", c.host, err)
		}
		if encoded[0] != c.typ {
			t.Errorf("%s: type = 0x%02x, want 0x%02x", c.host, encoded[0], c.typ)
		}

		host, port, consumed, err := readTUICAddr(encoded)
		if err != nil {
			t.Fatalf("decode %s: %v", c.host, err)
		}
		if host != c.host {
			t.Errorf("host = %q, want %q", host, c.host)
		}
		if port != c.port {
			t.Errorf("port = %d, want %d", port, c.port)
		}
		if consumed != len(encoded) {
			t.Errorf("consumed = %d, want %d", consumed, len(encoded))
		}
	}

	if _, err := encodeTUICAddr("example.com", 0); err == nil {
		t.Error("expected error for invalid port")
	}
	if _, err := encodeTUICAddr("example.com", 70000); err == nil {
		t.Error("expected error for out-of-range port")
	}
}

func TestTUICAddrNone(t *testing.T) {
	// The None marker is used by non-first fragments and carries no address.
	host, port, consumed, err := readTUICAddr([]byte{tuicAddrNone, 0x01, 0xBB})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if host != "" || port != 443 {
		t.Errorf("host = %q port = %d, want empty and 443", host, port)
	}
	if consumed != 3 {
		t.Errorf("consumed = %d, want 3", consumed)
	}
}

func TestTUICAddrTruncated(t *testing.T) {
	for _, bad := range [][]byte{
		{},
		{tuicAddrDomain},
		{tuicAddrDomain, 10, 'a'},
		{tuicAddrIPv4, 1, 2, 3},
		{tuicAddrIPv6, 1},
	} {
		if _, _, _, err := readTUICAddr(bad); err == nil {
			t.Errorf("expected an error for % x", bad)
		}
	}
}

// TestTUICPacketParsing checks the Packet command layout, in particular that
// SIZE counts the address header as well as the payload.
func TestTUICPacketParsing(t *testing.T) {
	addr, err := encodeTUICAddr("target.test", 443)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	payload := []byte("hello")

	frame := make([]byte, 0, 11+len(addr)+len(payload))
	frame = append(frame, tuicVersion, tuicCmdPacket)
	var ids [4]byte
	binary.BigEndian.PutUint16(ids[0:2], 7) // assoc id
	binary.BigEndian.PutUint16(ids[2:4], 9) // packet id
	frame = append(frame, ids[:]...)
	frame = append(frame, 1, 0) // single fragment
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(addr)+len(payload)))
	frame = append(frame, size[:]...)
	frame = append(frame, addr...)
	frame = append(frame, payload...)

	got, source, ok := parseTUICPacket(frame)
	if !ok {
		t.Fatal("parseTUICPacket rejected a well-formed frame")
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if source.Fqdn != "target.test" || source.Port != 443 {
		t.Errorf("source = %s, want target.test:443", source)
	}

	// A frame for a different command must be ignored rather than mis-parsed.
	if _, _, ok := parseTUICPacket([]byte{tuicVersion, tuicCmdHeartbeat}); ok {
		t.Error("a heartbeat must not be parsed as a packet")
	}
	if _, _, ok := parseTUICPacket([]byte{tuicVersion, tuicCmdPacket}); ok {
		t.Error("a truncated packet must be rejected")
	}
}

// tuicQUICServer runs a QUIC endpoint that speaks enough of the v5 protocol to
// accept an Authenticate command and echo a Connect stream. It is written from
// the specification rather than from the client code.
func tuicQUICServer(t *testing.T) (addr string, stop func()) {
	t.Helper()

	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
	}, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}

	go func() {
		for {
			session, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go handleTUICSession(session)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func handleTUICSession(session *quic.Conn) {
	// Authenticate arrives on a unidirectional stream while Connect uses
	// bidirectional ones, so the two are accepted separately. Accepting the
	// wrong kind would stall both.
	go func() {
		stream, err := session.AcceptUniStream(context.Background())
		if err != nil {
			return
		}
		header := make([]byte, 2+16+32)
		if _, err := io.ReadFull(stream, header); err != nil {
			return
		}
		stream.CancelRead(0)
	}()

	for {
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleTUICConnect(stream)
	}
}

func handleTUICConnect(s *quic.Stream) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(s, head); err != nil {
		return
	}
	if head[0] != tuicVersion || head[1] != tuicCmdConnect {
		return
	}

	// A QUIC stream has no message boundaries, so the address is consumed
	// byte-exactly before any payload that follows it.
	if err := skipTUICAddr(s); err != nil {
		return
	}

	line, err := readStreamLine(s)
	if err != nil && line == "" {
		return
	}
	s.Write([]byte(toUpper(trimLine(line)) + " "))
	s.Close()
}

// skipTUICAddr reads and discards one TUIC address from a stream.
func skipTUICAddr(r io.Reader) error {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return err
	}

	var need int
	switch first[0] {
	case tuicAddrDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return err
		}
		need = int(l[0]) + 2
	case tuicAddrIPv4:
		need = 4 + 2
	case tuicAddrIPv6:
		need = 16 + 2
	case tuicAddrNone:
		need = 2
	default:
		return io.ErrUnexpectedEOF
	}

	buf := make([]byte, need)
	_, err := io.ReadFull(r, buf)
	return err
}

func readStreamLine(s *quic.Stream) (string, error) {
	var out []byte
	one := make([]byte, 1)
	for len(out) < 4096 {
		n, err := s.Read(one)
		if n == 0 || err != nil {
			return trimLine(string(out)), err
		}
		if one[0] == '\n' {
			return trimLine(string(out)), nil
		}
		out = append(out, one[0])
	}
	return string(out), nil
}

func TestDialTUICEndToEnd(t *testing.T) {
	addr, stop := tuicQUICServer(t)
	defer stop()

	host, port := SplitHostPort(addr, 0)
	node := Node{
		Name: "tuic-node", Type: "tuic",
		Server: host, Port: port,
		Options: map[string]string{
			"uuid":             "11111111-2222-3333-4444-555555555555",
			"password":         "secret",
			"skip-cert-verify": "true",
			"servername":       "example.com",
		},
	}

	conn, err := node.Dial("target.test", 443)
	if err != nil {
		t.Fatalf("dial tuic: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte("tuic\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The server closes the stream right after replying, so the final read can
	// return the payload together with io.EOF.
	got := make([]byte, 32)
	n, err := conn.Read(got)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if string(got[:n]) != "TUIC " {
		t.Errorf("got %q, want %q", got[:n], "TUIC ")
	}
}

func TestTUICRequiresCredentials(t *testing.T) {
	base := Node{Name: "t", Type: "tuic", Server: "127.0.0.1", Port: 1, Options: map[string]string{}}

	noUUID := base
	noUUID.Options = map[string]string{"password": "x"}
	if _, err := noUUID.Dial("a.test", 443); err == nil {
		t.Error("expected an error when the uuid is missing")
	}

	noPassword := base
	noPassword.Options = map[string]string{"uuid": "11111111-2222-3333-4444-555555555555"}
	if _, err := noPassword.Dial("a.test", 443); err == nil {
		t.Error("expected an error when the password is missing")
	}
}

func TestTUICSupported(t *testing.T) {
	if !(Node{Type: "tuic"}).Supported() {
		t.Error("tuic should be reported as supported")
	}
}
