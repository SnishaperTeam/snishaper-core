package proxy

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SnishaperTeam/snishaper-core/subscription"
)

// TestSubscriptionNodeCarriesTraffic proves a rule bound to a subscription node
// is tunnelled through that node instead of dialling the origin directly.
func TestSubscriptionNodeCarriesTraffic(t *testing.T) {
	// A local SOCKS5 relay stands in for the subscription node, and a local
	// HTTP origin stands in for the destination.
	origin := startHTTPOrigin(t)
	originHost, originPort := subscription.SplitHostPort(origin.addr, 0)

	upstream := startCountingSocks5(t)
	upstreamHost, upstreamPort := subscription.SplitHostPort(upstream.addr, 0)

	store := subscription.NewStore(filepath.Join(t.TempDir(), "subscriptions.json"), nil)
	entry := store.AddEntryForTest("prov", "https://example.com/sub")
	store.SetNodesForTest(entry.ID, []subscription.Node{{
		Name: "socks-node", Type: "socks5",
		Server: upstreamHost, Port: upstreamPort,
	}})
	store.SetGroupsForTest(entry.ID, []subscription.Group{{
		Name: "Proxy", Type: "select", Members: []string{"socks-node"},
	}})
	if err := store.SelectNode(entry.ID, "Proxy", "socks-node"); err != nil {
		t.Fatalf("SelectNode: %v", err)
	}
	if err := store.SetActive(entry.ID); err != nil {
		t.Fatalf("SetActive: %v", err)
	}

	p := NewProxyServer("127.0.0.1:0")
	p.SetSubscriptionDialer(store)

	conn, ok, err := p.dialThroughSubscription(net.JoinHostPort(originHost, strconv.Itoa(originPort)))
	if err != nil {
		t.Fatalf("dialThroughSubscription: %v", err)
	}
	if !ok {
		t.Fatal("expected the subscription node to handle the connection")
	}
	defer conn.Close()

	// The node is a real relay, so the tunnel reaches the local origin and the
	// response body proves the bytes travelled end to end.
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "FLOWWEAVER-SUB-TEST") {
		t.Errorf("unexpected reply %q", body)
	}

	if got := upstream.connections(); got == 0 {
		t.Error("the node was not actually used to carry the traffic")
	}
}

func TestSubscriptionDialerFallsBackWhenNoNode(t *testing.T) {
	store := subscription.NewStore(filepath.Join(t.TempDir(), "subscriptions.json"), nil)
	// The built-in subscription has no nodes at all.
	p := NewProxyServer("127.0.0.1:0")
	p.SetSubscriptionDialer(store)

	conn, ok, err := p.dialThroughSubscription("example.com:443")
	if ok {
		t.Fatal("expected no node to be used for the built-in subscription")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn != nil {
		conn.Close()
	}
}

func TestSubscriptionDialerNilSafe(t *testing.T) {
	p := NewProxyServer("127.0.0.1:0")
	conn, ok, err := p.dialThroughSubscription("example.com:443")
	if ok || err != nil || conn != nil {
		t.Error("a server without a subscription dialer must fall through silently")
	}
}

func TestSubscriptionNodeUnsupportedProtocol(t *testing.T) {
	store := subscription.NewStore(filepath.Join(t.TempDir(), "subscriptions.json"), nil)
	entry := store.AddEntryForTest("prov", "https://example.com/sub")
	store.SetNodesForTest(entry.ID, []subscription.Node{{
		// juicity has no client in this package.
		Name: "jc", Type: "juicity", Server: "127.0.0.1", Port: 1,
	}})
	store.SetGroupsForTest(entry.ID, []subscription.Group{{
		Name: "Proxy", Members: []string{"jc"},
	}})
	if err := store.SelectNode(entry.ID, "Proxy", "jc"); err != nil {
		t.Fatalf("SelectNode: %v", err)
	}
	if err := store.SetActive(entry.ID); err != nil {
		t.Fatalf("SetActive: %v", err)
	}

	p := NewProxyServer("127.0.0.1:0")
	p.SetSubscriptionDialer(store)

	// An unsupported protocol must be skipped so traffic still flows via the
	// direct path instead of failing outright.
	conn, ok, err := p.dialThroughSubscription("example.com:443")
	if err != nil {
		t.Errorf("unsupported protocol must not surface an error, got %v", err)
	}
	if ok {
		t.Error("an unsupported protocol must not claim the connection")
	}
	if conn != nil {
		conn.Close()
	}
}

// countingSocks5 is a SOCKS5 server that records how many connections it
// served.
type countingSocks5 struct {
	addr string
	mu   chan struct{}
}

// startCountingSocks5 starts a SOCKS5 server that records how many connections
// it served and then relays bytes to the requested target, so a tunnel through
// it behaves like a real proxy.
func startCountingSocks5(t *testing.T) *countingSocks5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	c := &countingSocks5{addr: ln.Addr().String(), mu: make(chan struct{}, 16)}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case c.mu <- struct{}{}:
			default:
			}
			go func(x net.Conn) {
				defer x.Close()
				head := make([]byte, 2)
				if _, err := io.ReadFull(x, head); err != nil {
					return
				}
				methods := make([]byte, int(head[1]))
				if _, err := io.ReadFull(x, methods); err != nil {
					return
				}
				if _, err := x.Write([]byte{0x05, 0x00}); err != nil {
					return
				}

				req := make([]byte, 3)
				if _, err := io.ReadFull(x, req); err != nil {
					return
				}
				target, err := readSocksTarget(x)
				if err != nil {
					return
				}
				if _, err := x.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}

				up, err := net.DialTimeout("tcp", target, 5*time.Second)
				if err != nil {
					return
				}
				defer up.Close()

				done := make(chan struct{}, 2)
				go func() { io.Copy(up, x); done <- struct{}{} }()
				go func() { io.Copy(x, up); done <- struct{}{} }()
				<-done
			}(conn)
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return c
}

func (c *countingSocks5) connections() int { return len(c.mu) }

// readSocksTarget reads ATYP + ADDR + PORT after VER/CMD/RSV were consumed and
// returns the address as a dialable string.
func readSocksTarget(conn net.Conn) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(conn, atyp[:]); err != nil {
		return "", err
	}

	var host string
	switch atyp[0] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", err
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = string(buf)
	default:
		return "", fmt.Errorf("unsupported atyp 0x%02x", atyp[0])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return "", err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func drainSocksAddr(conn net.Conn) error {
	var atyp [1]byte
	if _, err := io.ReadFull(conn, atyp[:]); err != nil {
		return err
	}
	var n int
	switch atyp[0] {
	case 0x01:
		n = 4
	case 0x04:
		n = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		n = int(l[0])
	default:
		return io.ErrUnexpectedEOF
	}
	buf := make([]byte, n+2)
	_, err := io.ReadFull(conn, buf)
	return err
}

func readCRLFLine(conn net.Conn) (string, error) {
	var out []byte
	buf := make([]byte, 1)
	for len(out) < 4096 {
		n, err := conn.Read(buf)
		if n == 0 || err != nil {
			return strings.TrimRight(string(out), "\r"), err
		}
		if buf[0] == '\n' {
			return strings.TrimRight(string(out), "\r"), nil
		}
		out = append(out, buf[0])
	}
	return string(out), nil
}
