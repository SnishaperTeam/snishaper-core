package subscription

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// shadowsocksUDPEchoServer implements the server side of the Shadowsocks UDP
// relay: each datagram is decrypted under its own salt, the leading SOCKS5
// address is honoured, and the payload comes back through the same socket.
func shadowsocksUDPEchoServer(t *testing.T, spec shadowsocksSpec, password string) (addr string, stop func()) {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	passwordKey := shadowsocksKey(password, spec.keySize)

	go func() {
		raw := make([]byte, 65535)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, from, err := conn.ReadFrom(raw)
			if err != nil {
				return
			}
			// Copy the datagram: the shared read buffer is reused by the next
			// iteration while the goroutine is still decrypting.
			packet := make([]byte, n)
			copy(packet, raw[:n])
			go func(packet []byte, client net.Addr) {
				if len(packet) < spec.saltSize {
					return
				}
				salt := packet[:spec.saltSize]
				subkey, err := hkdfSHA1(passwordKey, salt, []byte("ss-subkey"), spec.keySize)
				if err != nil {
					return
				}
				aead, err := spec.factory(subkey)
				if err != nil {
					return
				}
				plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), packet[spec.saltSize:], nil)
				if err != nil {
					return
				}

				// The reply keeps the address header and echoes the payload, because the
				// client decodes the source from it. It is sealed under a fresh
				// salt, as every datagram in both directions must be.
				echoed, err := sealWith(spec, passwordKey, plain)
				if err != nil {
					return
				}
				if _, werr := conn.WriteTo(echoed, client); werr != nil {
					t.Errorf("server reply failed: %v", werr)
				}
			}(packet, from)
		}
	}()

	return conn.LocalAddr().String(), func() { conn.Close() }
}

func TestShadowsocksUDPRoundTrip(t *testing.T) {
	spec, ok := lookupShadowsocksSpec("aes-256-gcm")
	if !ok {
		t.Fatal("aes-256-gcm must be a known cipher")
	}

	const password = "ss-udp-password"
	serverAddr, stop := shadowsocksUDPEchoServer(t, spec, password)
	defer stop()

	host, port := SplitHostPort(serverAddr, 0)
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	node := Node{
		Name: "ss-udp", Type: "ss", Server: host, Port: port,
		Options: map[string]string{"cipher": "aes-256-gcm", "password": password},
	}
	conn, err := dialShadowsocksUDP(inner, node)
	if err != nil {
		t.Fatalf("dial ss udp: %v", err)
	}
	defer conn.Close()

	destination := M.Socksaddr{Fqdn: "target.test", Port: 443}
	payload := []byte("ss-udp-datagram")

	out := buf.New()
	out.Write(payload)
	if err := conn.WritePacket(out, destination); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	in := buf.New()
	defer in.Release()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	source, err := conn.ReadPacket(in)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if !bytes.Equal(in.Bytes(), payload) {
		t.Errorf("payload = %q, want %q", in.Bytes(), payload)
	}
	if source.Fqdn != "target.test" || source.Port != 443 {
		t.Errorf("source = %s, want target.test:443", source)
	}
}

func TestShadowsocksUDPPerPacketSalt(t *testing.T) {
	node := Node{
		Name: "ss", Type: "ss", Server: "127.0.0.1", Port: 1,
		Options: map[string]string{"cipher": "aes-256-gcm", "password": "pw"},
	}

	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer inner.Close()

	conn, err := dialShadowsocksUDP(inner, node)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	ss, ok := conn.(*shadowsocksUDPPacketConn)
	if !ok {
		t.Fatalf("unexpected conn type %T", conn)
	}

	// Two seals of the same payload must differ because the salt is random.
	first, err := ss.seal([]byte("same-payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	second, err := ss.seal([]byte("same-payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Error("each datagram must use a fresh salt")
	}

	// Both must still open back to the original payload.
	for i, packet := range [][]byte{first, second} {
		plain, err := ss.open(packet)
		if err != nil {
			t.Fatalf("open packet %d: %v", i, err)
		}
		if string(plain) != "same-payload" {
			t.Errorf("packet %d decrypted to %q", i, plain)
		}
	}
}

func TestShadowsocksUDPRejectsForeignPacket(t *testing.T) {
	spec, ok := lookupShadowsocksSpec("aes-256-gcm")
	if !ok {
		t.Fatal("aes-256-gcm must be a known cipher")
	}
	node := Node{
		Name: "ss", Type: "ss", Server: "127.0.0.1", Port: 1,
		Options: map[string]string{"cipher": "aes-256-gcm", "password": "pw"},
	}
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer inner.Close()

	conn, err := dialShadowsocksUDP(inner, node)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	ss := conn.(*shadowsocksUDPPacketConn)

	// A packet sealed with a different password must not authenticate.
	otherKey := shadowsocksKey("another-password", spec.keySize)
	salt := make([]byte, spec.saltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	subkey, err := hkdfSHA1(otherKey, salt, []byte("ss-subkey"), spec.keySize)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	aead, err := spec.factory(subkey)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	foreign := append(salt, aead.Seal(nil, make([]byte, aead.NonceSize()), []byte("nope"), nil)...)

	if _, err := ss.open(foreign); err == nil {
		t.Error("a datagram sealed with another password must be rejected")
	}

	// A packet shorter than the salt is malformed.
	if _, err := ss.open([]byte{0x01}); err == nil {
		t.Error("a runt datagram must be rejected")
	}
}

func TestShadowsocksUDPRejectsLegacyCipher(t *testing.T) {
	node := Node{
		Name: "ss", Type: "ss", Server: "127.0.0.1", Port: 1,
		Options: map[string]string{"cipher": "aes-256-cfb", "password": "pw"},
	}
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer inner.Close()

	if _, err := dialShadowsocksUDP(inner, node); err == nil {
		t.Error("expected an error for a legacy stream cipher")
	}
}

func TestReadSocksAddrBytes(t *testing.T) {
	// Domain form.
	domain := append([]byte{0x03, 0x0b}, []byte("target.test")...)
	domain = append(domain, 0x01, 0xBB)
	addr, consumed, err := readSocksAddrBytes(domain)
	if err != nil {
		t.Fatalf("decode domain: %v", err)
	}
	if addr.Fqdn != "target.test" || addr.Port != 443 || consumed != len(domain) {
		t.Errorf("domain = %s consumed = %d", addr, consumed)
	}

	// IPv4 form.
	v4 := []byte{0x01, 1, 2, 3, 4, 0x00, 0x50}
	addr, consumed, err = readSocksAddrBytes(v4)
	if err != nil {
		t.Fatalf("decode v4: %v", err)
	}
	if addr.Addr.String() != "1.2.3.4" || addr.Port != 80 || consumed != 7 {
		t.Errorf("v4 = %s consumed = %d", addr, consumed)
	}

	// Truncated input must be reported.
	if _, _, err := readSocksAddrBytes([]byte{0x01, 1, 2}); err == nil {
		t.Error("expected an error for a truncated address")
	}
	if _, _, err := readSocksAddrBytes(nil); err == nil {
		t.Error("expected an error for an empty buffer")
	}
}

// sealWith encrypts a datagram the way a Shadowsocks server does: a fresh
// random salt, an HKDF subkey derived from it, and one AEAD message.
func sealWith(spec shadowsocksSpec, passwordKey, payload []byte) ([]byte, error) {
	salt := make([]byte, spec.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	subkey, err := hkdfSHA1(passwordKey, salt, []byte("ss-subkey"), spec.keySize)
	if err != nil {
		return nil, err
	}
	aead, err := spec.factory(subkey)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, make([]byte, aead.NonceSize()), payload, nil)
	return append(salt, sealed...), nil
}
