package subscription

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// vlessEchoServer answers the VLESS header then echoes uppercased lines.
func vlessEchoServer(t *testing.T, cert tls.Certificate) (addr string, stop func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleVLESSEcho(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func handleVLESSEcho(conn net.Conn) {
	defer conn.Close()

	// version(1) uuid(16) addonsLen(1) command(1) port(2) atyp(1)
	head := make([]byte, 1+16+1+1+2+1)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}

	// Address type follows the VLESS spec: 0x01 IPv4, 0x02 domain, 0x03 IPv6.
	switch head[1+16+1+1+2] {
	case 0x01:
		if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
			return
		}
	case 0x02:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, int(l[0]))); err != nil {
			return
		}
	case 0x03:
		if _, err := io.ReadFull(conn, make([]byte, 16)); err != nil {
			return
		}
	}

	if _, err := conn.Write([]byte{0x00, 0x00}); err != nil {
		return
	}

	line, _ := readTestLine(conn)
	conn.Write([]byte(strings.ToUpper(line) + " "))
}

// vlessWSServer accepts a WebSocket upgrade and then runs the VLESS exchange.
func vlessWSServer(t *testing.T, cert tls.Certificate) (addr string, stop func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + wsAcceptKey(key) + "\r\n\r\n"
		if _, err := conn.Write([]byte(resp)); err != nil {
			return
		}

		server := &websocketConn{Conn: conn, reader: buf.Reader, mask: false}
		payload, err := server.ReadBinary()
		if err != nil {
			return
		}
		_ = payload

		// Echo a token back, then keep relaying so the client can read it.
		if err := server.WriteBinary(append([]byte{0x00, 0x00}, []byte("VLESSEXTHELLO ")...)); err != nil {
			return
		}
		relayBuf := make([]byte, 512)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := server.Read(relayBuf)
			if err != nil {
				return
			}
			if n == 0 {
				return
			}
			if err := server.WriteBinary(relayBuf[:n]); err != nil {
				return
			}
		}
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)

	return ln.Addr().String(), func() { ln.Close(); srv.Close() }
}

func wsAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	sum := sha1.Sum([]byte(magic + key))
	return base64Encode(sum[:])
}

func TestDialVLESSOverTCP(t *testing.T) {
	cert := selfSignedCert(t)
	addr, stop := vlessEchoServer(t, cert)
	defer stop()

	host, port := SplitHostPort(addr, 0)
	node := Node{
		Name: "vless-tcp", Type: "vless",
		Server: host, Port: port,
		Options: map[string]string{
			"uuid":             testVMessUUID,
			"network":          "tcp",
			"tls":              "true",
			"skip-cert-verify": "true",
			"servername":       "example.com",
		},
	}

	conn, err := node.Dial("target.test", 443)
	if err != nil {
		t.Fatalf("dial vless: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("vless\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 32)
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(string(got[:n]), "VLESS") {
		t.Errorf("unexpected reply %q", got[:n])
	}
}

func TestDialVLESSOverWebsocket(t *testing.T) {
	cert := selfSignedCert(t)
	addr, stop := vlessWSServer(t, cert)
	defer stop()

	host, port := SplitHostPort(addr, 0)
	node := Node{
		Name: "vless-ws", Type: "vless",
		Server: host, Port: port,
		Options: map[string]string{
			"uuid":             testVMessUUID,
			"network":          "ws",
			"path":             "/ray",
			"host":             "example.com",
			"tls":              "true",
			"skip-cert-verify": "true",
			"servername":       "example.com",
		},
	}

	conn, err := node.Dial("target.test", 443)
	if err != nil {
		t.Fatalf("dial vless ws: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 64)
	n, err := conn.Read(got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(got[:n]), "VLESSEXTHELLO") {
		t.Errorf("unexpected reply %q", got[:n])
	}
}

func TestVLESSHeaderLayout(t *testing.T) {
	uuid, err := parseUUID(testVMessUUID)
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}

	// Domain target.
	header, err := buildVLESSHeader(uuid, 0x01, "example.com", 443)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	if header[0] != 0x00 {
		t.Errorf("version = %d", header[0])
	}
	idx := 1 + 16
	if header[idx] != 0x00 {
		t.Errorf("addons length = %d", header[idx])
	}
	idx++
	if header[idx] != 0x01 {
		t.Errorf("command = %d, want 0x01 (tcp)", header[idx])
	}
	idx++
	if binary.BigEndian.Uint16(header[idx:idx+2]) != 443 {
		t.Errorf("port not big endian")
	}
	idx += 2
	if header[idx] != 0x02 {
		t.Errorf("address type = %d, want 0x02 (domain)", header[idx])
	}

	// IPv4 target.
	header, err = buildVLESSHeader(uuid, 0x01, "1.2.3.4", 80)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	idx = 1 + 16 + 1 + 1 + 2
	if header[idx] != 0x01 {
		t.Errorf("address type = %d, want 0x01 (ipv4)", header[idx])
	}

	if _, err := buildVLESSHeader(uuid, 0x01, "example.com", 0); err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestVLESSSupported(t *testing.T) {
	if !(Node{Type: "vless"}).Supported() {
		t.Error("vless should be supported")
	}
}

func readTestLine(conn net.Conn) (string, error) {
	reader := bufio.NewReaderSize(conn, 1)
	var out []byte
	buf := make([]byte, 1)
	for len(out) < 4096 {
		n, err := reader.Read(buf)
		if n == 0 || err != nil {
			return strings.TrimRight(string(out), "\r\n"), err
		}
		if buf[0] == '\n' {
			return strings.TrimRight(string(out), "\r"), nil
		}
		out = append(out, buf[0])
	}
	return string(out), nil
}

// vlessUDPEchoServer speaks the server side of VLESS UDP plain mode: it reads
// the request header, answers with the two byte reply header, and echoes the
// datagram payload back.
func vlessUDPEchoServer(t *testing.T, cert tls.Certificate) (addr string, stop func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleVLessUDPEcho(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// vlessUDPEchoPayloadLen is the datagram size used by the round trip test. The
// server echoes exactly this many bytes because the client waits for the same
// count it sent.
const vlessUDPEchoPayloadLen = 18

func handleVLessUDPEcho(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	head := make([]byte, 1+16+1+1+2+1)
	if _, err := io.ReadFull(reader, head); err != nil {
		return
	}
	if head[0] != 0x00 {
		return
	}
	command := head[1+16+1]
	if command != 0x02 && command != 0x01 {
		return
	}

	// Consume the address so the payload starts cleanly. The address type
	// follows the VLESS convention: 0x01 IPv4, 0x02 domain, 0x03 IPv6.
	switch head[1+16+1+1+2] {
	case 0x01:
		// The port is part of the fixed header, so only the address remains.
		if _, err := io.ReadFull(reader, make([]byte, 4)); err != nil {
			return
		}
	case 0x02:
		var l [1]byte
		if _, err := io.ReadFull(reader, l[:]); err != nil {
			return
		}
		// Only the name follows; the port is already in the fixed header.
		if _, err := io.ReadFull(reader, make([]byte, int(l[0]))); err != nil {
			return
		}
	case 0x03:
		if _, err := io.ReadFull(reader, make([]byte, 16)); err != nil {
			return
		}
	}

	// Reply header, then echo the payload back. The client waits for exactly as
	// many bytes as it sent, so the payload length has to match.
	if _, err := conn.Write([]byte{0x00, 0x00}); err != nil {
		return
	}

	buf := make([]byte, vlessUDPEchoPayloadLen)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return
	}
	_, _ = conn.Write(buf)
}

func TestVLessUDPRoundTrip(t *testing.T) {
	cert := selfSignedCert(t)
	addr, stop := vlessUDPEchoServer(t, cert)
	defer stop()

	host, port := SplitHostPort(addr, 0)
	node := Node{
		Name: "vless-udp", Type: "vless",
		Server: host, Port: port,
		Options: map[string]string{
			"uuid":             testVMessUUID,
			"network":          "tcp",
			"tls":              "true",
			"skip-cert-verify": "true",
			"servername":       "example.com",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pkt, err := node.ListenPacketUDP(ctx, M.Socksaddr{Fqdn: "target.test", Port: 443})
	if err != nil {
		t.Fatalf("ListenPacketUDP: %v", err)
	}
	defer pkt.Close()

	destination := M.Socksaddr{Fqdn: "target.test", Port: 443}
	payload := []byte("vless-udp-datagram")

	out := buf.New()
	out.Write(payload)
	if err := pkt.WritePacket(out, destination); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	in := buf.New()
	defer in.Release()
	source, err := pkt.ReadPacket(in)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if in.Len() != len(payload) {
		t.Fatalf("payload = %q, want %q", in.Bytes(), payload)
	}
	if source.Fqdn != "target.test" {
		t.Errorf("source = %s, want target.test", source)
	}
}
