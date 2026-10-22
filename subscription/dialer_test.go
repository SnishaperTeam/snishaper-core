package subscription

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

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

// TestHandBuiltCryptoProtocolsError proves the removed hand-rolled dialers
// fail loudly instead of silently dialing out.
func TestHandBuiltCryptoProtocolsError(t *testing.T) {
	for _, typ := range []string{"ss", "vmess", "vless", "trojan", "tuic", "hysteria2"} {
		node := Node{Name: "n", Type: typ, Server: "127.0.0.1", Port: 1}
		if _, err := node.Dial("a.test", 443); err == nil {
			t.Errorf("%s: expected an error for a hand-built node", typ)
		}
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

func toUpper(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'a' && out[i] <= 'z' {
			out[i] -= 32
		}
	}
	return string(out)
}
