package subscription

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// trojanUDPEchoServer implements the server side of Trojan UDP-over-TCP,
// following the sing-box compatibility notes byte for byte:
//
//	[key][CRLF][0x03][addr][CRLF][addr][len][CRLF][payload]
//
// It is deliberately written from the specification rather than from the
// client code, so a shared misunderstanding cannot make a broken client pass.
func trojanUDPEchoServer(t *testing.T, cert tls.Certificate) (addr string, stop func()) {
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
			go handleTrojanUDPEcho(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func handleTrojanUDPEcho(conn net.Conn) {
	defer conn.Close()

	// key(56) + CRLF + command(1), then the address, then CRLF.
	var head [56 + 2 + 1]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return
	}
	if head[56] != 0x0d || head[57] != 0x0a {
		return
	}
	if head[58] != trojanCommandUDP {
		// The client must announce the UDP command; a TCP-only handshake
		// would land here with 0x01 and must not be accepted.
		return
	}

	handshakeAddr, err := M.SocksaddrSerializer.ReadAddrPort(conn)
	if err != nil {
		return
	}
	var crlf [2]byte
	if _, err := io.ReadFull(conn, crlf[:]); err != nil {
		return
	}
	_ = handshakeAddr

	readAndEcho := func() error {
		destination, err := M.SocksaddrSerializer.ReadAddrPort(conn)
		if err != nil {
			return err
		}
		var lengthBuf [2]byte
		if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint16(lengthBuf[:]))
		if length < 2 {
			return io.ErrUnexpectedEOF
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(conn, body); err != nil {
			return err
		}
		payload := body[2:] // strip the framing CRLF

		addrWriter := buf.NewSize(M.SocksaddrSerializer.AddrPortLen(destination))
		defer addrWriter.Release()
		if err := M.SocksaddrSerializer.WriteAddrPort(addrWriter, destination); err != nil {
			return err
		}

		reply := make([]byte, 0, len(addrWriter.Bytes())+4+len(payload))
		reply = append(reply, addrWriter.Bytes()...)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(payload)+2))
		reply = append(reply, l[:]...)
		reply = append(reply, 0x0d, 0x0a)
		reply = append(reply, payload...)

		_, err = conn.Write(reply)
		return err
	}

	for {
		if err := readAndEcho(); err != nil {
			return
		}
	}
}

func TestDialTrojanUDPEndToEnd(t *testing.T) {
	cert := selfSignedCert(t)
	addr, stop := trojanUDPEchoServer(t, cert)
	defer stop()

	host, port := SplitHostPort(addr, 0)
	node := Node{
		Name: "trojan-udp", Type: "trojan",
		Server: host, Port: port,
		Options: map[string]string{
			"password":         "hunter2",
			"skip-cert-verify": "true",
			"servername":       "example.com",
		},
	}

	// Use a domain destination so the SOCKS5 serializer takes the FQDN path
	// in both directions.
	destination := M.ParseSocksaddr("target.test:443")
	if !destination.IsDomain() {
		t.Fatalf("destination should be a domain, got %s", destination)
	}

	pkt, err := node.ListenPacketUDP(testContext(t), destination)
	if err != nil {
		t.Fatalf("ListenPacketUDP: %v", err)
	}
	defer pkt.Close()

	_ = pkt.SetDeadline(time.Now().Add(8 * time.Second))

	out := buf.New()
	out.Write([]byte("trojan-udp"))
	if err := pkt.WritePacket(out, destination); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	in := buf.New()
	defer in.Release()
	source, err := pkt.ReadPacket(in)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if got := string(in.Bytes()); got != "trojan-udp" {
		t.Errorf("got %q, want %q", got, "trojan-udp")
	}
	if source.Fqdn != "target.test" {
		t.Errorf("source = %s, want the destination domain", source)
	}
}

// TestTrojanHandshakeCarriesTCPCommand guards the byte the client must send
// between the CRLF and the address. A missing command byte once made the
// client and its test agree on a frame no real server accepts.
func TestTrojanHandshakeCarriesTCPCommand(t *testing.T) {
	cert := selfSignedCert(t)
	addr, stop := trojanEchoServerStrict(t, cert)
	defer stop()

	host, port := SplitHostPort(addr, 0)
	node := Node{
		Name: "trojan-tcp", Type: "trojan",
		Server: host, Port: port,
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

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The echo server terminates its reply with a space.
	if got := strings.TrimSpace(string(buf[:n])); got != "HELLO" {
		t.Errorf("got %q, want HELLO", got)
	}
}

// trojanEchoServerStrict validates the command byte and refuses the
// connection when it is absent or wrong.
func trojanEchoServerStrict(t *testing.T, cert tls.Certificate) (addr string, stop func()) {
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
			go func(c net.Conn) {
				defer c.Close()
				// key(56) + CRLF + command(1)
				var head [56 + 2 + 1]byte
				if _, err := io.ReadFull(c, head[:]); err != nil {
					return
				}
				if head[56] != 0x0d || head[57] != 0x0a {
					return
				}
				if head[58] != trojanCommandTCP {
					return
				}
				if _, err := M.SocksaddrSerializer.ReadAddrPort(c); err != nil {
					return
				}
				var crlf [2]byte
				if _, err := io.ReadFull(c, crlf[:]); err != nil {
					return
				}
				line, _ := readLine(c)
				c.Write([]byte(toUpper(trimLine(line)) + " "))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}
