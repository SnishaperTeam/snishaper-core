package proxy

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SnishaperTeam/snishaper-core/subscription"
)

// TestFullChainThroughSubscriptionNode wires the real proxy server to a
// subscription node and drives an end-to-end HTTP request through it. This is
// the proof that a selected node actually carries live traffic.
func TestFullChainThroughSubscriptionNode(t *testing.T) {
	origin := startHTTPOrigin(t)

	node := startCountingSocks5(t)
	nodeHost, nodePort := subscription.SplitHostPort(node.addr, 0)

	store := subscription.NewStore(filepath.Join(t.TempDir(), "subscriptions.json"), nil)
	entry := store.AddEntryForTest("prov", "https://example.com/sub")
	store.SetNodesForTest(entry.ID, []subscription.Node{{
		Name: "socks-node", Type: "socks5", Server: nodeHost, Port: nodePort,
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

	// The router needs a rule set; a catch-all regex in transparent mode makes
	// the request travel over the subscription tunnel without extra TLS work
	// (the test speaks plain HTTP end to end).
	rm := NewRuleManager(
		filepath.Join(t.TempDir(), "settings.json"),
		filepath.Join(t.TempDir(), "config.json"),
	)
	rm.SetRules([]Rule{{Domain: "~.+", Mode: "transparent", Enabled: true}})
	p.SetRuleManager(rm)

	if err := p.SetMode("transparent"); err != nil {
		t.Fatalf("set mode: %v", err)
	}
	if err := p.SetListenAddr("127.0.0.1:0"); err != nil {
		t.Fatalf("set listen addr: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer p.Stop()

	p.mu.RLock()
	proxyAddr := p.mainListener.Addr().String()
	p.mu.RUnlock()

	originHost, originPort := subscription.SplitHostPort(origin.addr, 0)

	// Drive a CONNECT through the proxy's own SOCKS5 listener.
	client, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(originHost))}
	req = append(req, originHost...)
	req = append(req, byte(originPort>>8), byte(originPort))
	if _, err := client.Write(req); err != nil {
		t.Fatalf("connect req: %v", err)
	}

	resp := make([]byte, 3)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("proxy refused CONNECT, code %d", resp[1])
	}
	if err := drainSocksAddr(client); err != nil {
		t.Fatalf("bind addr: %v", err)
	}

	// The tunnel is a raw byte stream to the origin; the transparent path
	// forwards bytes without terminating TLS, so speak plain HTTP.
	client.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(client, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", originHost)

	body, err := io.ReadAll(client)
	if err != nil && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(string(body), "FLOWWEAVER-SUB-TEST") {
		t.Errorf("unexpected response body: %q", string(body))
	}

	if node.connections() == 0 {
		t.Error("traffic did not traverse the subscription node")
	}
}

// startHTTPOrigin runs a plain HTTP server that answers any request with a
// fixed marker body.
func startHTTPOrigin(t *testing.T) *countingSocks5 {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}

	srv := &countingSocks5{addr: ln.Addr().String(), mu: make(chan struct{}, 4)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				body := "FLOWWEAVER-SUB-TEST"
				header := "HTTP/1.1 200 OK" + "\r\n" +
					fmt.Sprintf("Content-Length: %d", len(body)) + "\r\n" +
					"Connection: close" + "\r\n\r\n"
				_, _ = c.Write([]byte(header + body))
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return srv
}
