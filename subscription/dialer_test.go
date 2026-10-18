package subscription

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// echoServer accepts one connection, reads a line, and writes it back uppercased.
func echoServer(t *testing.T, prefix string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if prefix != "" {
					buf := make([]byte, len(prefix))
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					if string(buf) != prefix {
						return
					}
				}
				line, _ := readLine(c)
				c.Write([]byte(toUpper(strings.TrimSpace(line)) + " "))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func readLine(c net.Conn) (string, error) {
	var out []byte
	buf := make([]byte, 1)
	for len(out) < 4096 {
		n, err := c.Read(buf)
		if n == 0 || err != nil {
			return string(out), err
		}
		if buf[0] == '\n' {
			// Strip a trailing CR so CRLF-terminated protocols parse cleanly.
			return strings.TrimRight(string(out), "\r"), nil
		}
		out = append(out, buf[0])
	}
	return string(out), nil
}

func TestDialSocks5EndToEnd(t *testing.T) {
	upstream, stop := socks5EchoServer(t)
	defer stop()

	serverHost, serverPort := SplitHostPort(upstream, 0)

	node := Node{
		Name: "socks-node", Type: "socks5",
		Server: serverHost, Port: serverPort,
	}

	conn, err := node.Dial("example.com", 80)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readUntilSpace(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "HELLO" {
		t.Errorf("got %q, want HELLO", got)
	}
}

// readUntilSpace reads a short token, which the echo servers terminate with a
// space rather than a newline.
func readUntilSpace(conn net.Conn) (string, error) {
	var out []byte
	buf := make([]byte, 1)
	for len(out) < 4096 {
		n, err := conn.Read(buf)
		if n == 0 || err != nil {
			return string(out), err
		}
		if buf[0] == ' ' || buf[0] == '\n' {
			return string(out), nil
		}
		out = append(out, buf[0])
	}
	return string(out), nil
}

// socks5EchoServer is a minimal SOCKS5 server that echoes uppercased lines.
func socks5EchoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSocks5Echo(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func handleSocks5Echo(conn net.Conn) {
	defer conn.Close()

	// Greeting: VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER CMD RSV then ATYP ADDR PORT.
	req := make([]byte, 3)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if err := drainSocks5Addr(conn); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	line, _ := readLine(conn)
	conn.Write([]byte(toUpper(strings.TrimSpace(line)) + " "))
}

// drainSocks5Addr consumes an address whose VER/CMD/RSV bytes were already read.
func drainSocks5Addr(conn net.Conn) error {
	var atyp [1]byte
	if _, err := io.ReadFull(conn, atyp[:]); err != nil {
		return err
	}
	switch atyp[0] {
	case 0x01:
		buf := make([]byte, 4+2)
		_, err := io.ReadFull(conn, buf)
		return err
	case 0x04:
		buf := make([]byte, 16+2)
		_, err := io.ReadFull(conn, buf)
		return err
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		buf := make([]byte, int(l[0])+2)
		_, err := io.ReadFull(conn, buf)
		return err
	default:
		return fmt.Errorf("unsupported atyp 0x%02x", atyp[0])
	}
}

func TestDialHTTPEndToEnd(t *testing.T) {
	addr, stop := httpConnectEchoServer(t)
	defer stop()

	serverHost, serverPort := SplitHostPort(addr, 0)
	node := Node{Name: "http-node", Type: "http", Server: serverHost, Port: serverPort}

	conn, err := node.Dial("example.com", 443)
	if err != nil {
		t.Fatalf("dial http: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readUntilSpace(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "PING" {
		t.Errorf("got %q, want PING", got)
	}
}

func httpConnectEchoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 0, 256)
				one := make([]byte, 1)
				for len(buf) < 1024 {
					n, err := c.Read(one)
					if err != nil || n == 0 {
						break
					}
					buf = append(buf, one[0])
					if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
						break
					}
				}
				c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				line, _ := readLine(c)
				c.Write([]byte(toUpper(strings.TrimSpace(line)) + " "))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestDialTrojanEndToEnd(t *testing.T) {
	cert := selfSignedCert(t)
	addr, stop := trojanEchoServerStrict(t, cert)
	defer stop()

	serverHost, serverPort := SplitHostPort(addr, 0)
	node := Node{
		Name: "trojan-node", Type: "trojan",
		Server: serverHost, Port: serverPort,
		Options: map[string]string{
			"password":         "hunter2",
			"skip-cert-verify": "true",
			"servername":       "example.com",
		},
	}

	conn, err := node.Dial("target.test", 443)
	if err != nil {
		t.Fatalf("dial trojan: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("secure\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readUntilSpace(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "SECURE" {
		t.Errorf("got %q, want SECURE", got)
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	certPEM, keyPEM := generateSelfSigned(t, key)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return cert
}

func TestDialShadowsocksRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	addr, stop := shadowsocksEchoServer(t, key, "aes-256-gcm", "password123")
	defer stop()

	serverHost, serverPort := SplitHostPort(addr, 0)
	node := Node{
		Name: "ss-node", Type: "ss",
		Server: serverHost, Port: serverPort,
		Options: map[string]string{
			"cipher":   "aes-256-gcm",
			"password": "password123",
		},
	}

	conn, err := node.Dial("target.test", 443)
	if err != nil {
		t.Fatalf("dial ss: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("stream\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readUntilSpace(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "STREAM" {
		t.Errorf("got %q, want STREAM", got)
	}
}

func TestUnsupportedCipher(t *testing.T) {
	node := Node{
		Name: "ss-legacy", Type: "ss", Server: "127.0.0.1", Port: 8388,
		Options: map[string]string{"cipher": "aes-256-cfb", "password": "x"},
	}
	if _, err := node.Dial("a.test", 443); err == nil {
		t.Error("expected error for legacy stream cipher")
	}
}

func TestNodeSupported(t *testing.T) {
	cases := map[string]bool{
		"ss": true, "vmess": true, "vless": true, "trojan": true, "socks5": true,
		"http": true, "tuic": true, "hysteria2": true,
		// Not implemented: these have no client in this package.
		"juicity": false, "anytls": false,
	}
	for typ, want := range cases {
		if got := (Node{Type: typ}).Supported(); got != want {
			t.Errorf("Node{%q}.Supported() = %v, want %v", typ, got, want)
		}
	}
}

func TestEncodeSocks5Addr(t *testing.T) {
	if _, err := EncodeSocks5Addr("", 80); err == nil {
		t.Error("expected error for empty host")
	}
	if _, err := EncodeSocks5Addr("a.test", 0); err == nil {
		t.Error("expected error for invalid port")
	}
	if _, err := EncodeSocks5Addr("a.test", 70000); err == nil {
		t.Error("expected error for out-of-range port")
	}

	addr, err := EncodeSocks5Addr("example.com", 443)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// The encoding is ATYP LEN DOMAIN PORT, without the VER byte.
	if addr[0] != 0x03 {
		t.Errorf("domain should use ATYP 0x03, got 0x%02x", addr[0])
	}
	if int(addr[1]) != len("example.com") {
		t.Errorf("domain length = %d", addr[1])
	}
	if binary.BigEndian.Uint16(addr[len(addr)-2:]) != 443 {
		t.Errorf("port not encoded correctly: % x", addr)
	}

	ip, err := EncodeSocks5Addr("1.2.3.4", 80)
	if err != nil {
		t.Fatalf("encode ip: %v", err)
	}
	if ip[1] != 0x01 {
		t.Errorf("IPv4 should use ATYP 0x01, got 0x%02x", ip[1])
	}
}

func TestShadowsocksKeyLength(t *testing.T) {
	for _, n := range []int{16, 24, 32} {
		if got := len(shadowsocksKey("pw", n)); got != n {
			t.Errorf("key length = %d, want %d", got, n)
		}
	}
}

func TestParseUUID(t *testing.T) {
	id, err := parseUUID("11111111-2222-3333-4444-555555555555")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if id[0] != 0x11 || id[15] != 0x55 {
		t.Errorf("uuid decoded wrong: %x", id)
	}
	if _, err := parseUUID("short"); err == nil {
		t.Error("expected error for short uuid")
	}
	if _, err := parseUUID("zzzzzzzz-2222-3333-4444-555555555555"); err == nil {
		t.Error("expected error for non-hex uuid")
	}
}

var (
	certOnce sync.Once
	certPEM  []byte
	keyPEM   []byte
)

func generateSelfSigned(t *testing.T, key []byte) ([]byte, []byte) {
	t.Helper()
	certOnce.Do(func() {
		certPEM, keyPEM = makeSelfSigned()
	})
	return certPEM, keyPEM
}

var _ = aes.NewCipher
var _ = cipher.NewGCM
var _ = sha256.Sum256
var _ = binary.BigEndian
var _ = fmt.Sprint
var _ = time.Now

func TestDialVMessEndToEnd(t *testing.T) {
	cert := selfSignedCert(t)
	addr, stop := vmessEchoServer(t, cert, true)
	defer stop()

	serverHost, serverPort := SplitHostPort(addr, 0)
	node := Node{
		Name: "vmess-node", Type: "vmess",
		Server: serverHost, Port: serverPort,
		Options: map[string]string{
			"uuid":             testVMessUUID,
			"method":           "auto",
			"tls":              "true",
			"skip-cert-verify": "true",
			"servername":       "example.com",
		},
	}

	conn, err := node.Dial("target.test", 443)
	if err != nil {
		t.Fatalf("dial vmess: %v", err)
	}
	defer conn.Close()
}

func TestDialVMessInvalidUUID(t *testing.T) {
	node := Node{
		Name: "bad", Type: "vmess", Server: "127.0.0.1", Port: 1,
		Options: map[string]string{"uuid": "not-a-uuid"},
	}
	if _, err := node.Dial("a.test", 443); err == nil {
		t.Error("expected error for invalid uuid")
	}
}
