package proxy

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/SnishaperTeam/snishaper-core/subscription"
)

// TestUDPThroughSubscriptionNode proves a UDP datagram reaches the destination
// by travelling through the selected subscription node, using the same sing
// N.PacketConn abstraction the TUN handler relies on.
func TestUDPThroughSubscriptionNode(t *testing.T) {
	// A UDP echo server stands in for the destination.
	echoAddr, stopEcho := startUDPEcho(t)
	defer stopEcho()
	echoHost, echoPort := subscription.SplitHostPort(echoAddr, 0)
	echoAddrUDP := &net.UDPAddr{IP: net.ParseIP(echoHost), Port: echoPort}

	// A SOCKS5 server with UDP ASSOCIATE support stands in for the node.
	nodeAddr, stopNode := startUDPRelaySocks5(t)
	defer stopNode()
	nodeHost, nodePort := subscription.SplitHostPort(nodeAddr, 0)

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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pkt, ok, err := p.OpenUDP(ctx, M.SocksaddrFromNet(echoAddrUDP))
	if err != nil {
		t.Fatalf("OpenUDP: %v", err)
	}
	if !ok {
		t.Fatal("expected the subscription node to handle UDP")
	}
	defer pkt.Close()

	// Exercise the sing-native path the TUN handler uses, so this test covers
	// the same abstraction the production relay relies on — including the
	// header room a SOCKS5 relay needs to frame each datagram.
	options := N.NewReadWaitOptions(nil, pkt)
	_ = pkt.SetDeadline(time.Now().Add(8 * time.Second))
	payload := []byte("hello-udp")

	outBuf := options.NewBufferSize(len(payload))
	outBuf.Write(payload)
	if err := pkt.WritePacket(outBuf, M.SocksaddrFromNet(echoAddrUDP)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	inBuf := options.NewBufferSize(buf.UDPBufferSize)
	defer inBuf.Release()
	_, err = pkt.ReadPacket(inBuf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	// The relay frames each datagram with an address, and for SOCKS5 UDP
	// associate that is the requested destination rather than the peer that
	// replied, so only the payload is meaningful here.
	if inBuf.Len() != len(payload) {
		t.Errorf("got %q, want %q", inBuf.Bytes(), payload)
	}
}

func TestUDPFallsBackWhenNodeCannotRelay(t *testing.T) {
	store := subscription.NewStore(filepath.Join(t.TempDir(), "subscriptions.json"), nil)
	// Built-in subscription: no node at all.
	p := NewProxyServer("127.0.0.1:0")
	p.SetSubscriptionDialer(store)

	_, ok, err := p.OpenUDP(context.Background(), M.ParseSocksaddr("example.com:53"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected no relay when the built-in subscription is active")
	}
}

func TestUDPNilSafe(t *testing.T) {
	p := NewProxyServer("127.0.0.1:0")
	_, ok, err := p.OpenUDP(context.Background(), M.ParseSocksaddr("example.com:53"))
	if ok || err != nil {
		t.Error("a server without a subscription dialer must fall through silently")
	}
}

func TestUDPSupportedByProtocol(t *testing.T) {
	// Every protocol FlowWeaver can dial carries UDP as well.
	yes := []string{"ss", "vmess", "vless", "wireguard", "socks5", "SOCKS5", "socks", "trojan", "tuic", "hysteria2"}
	for _, typ := range yes {
		if !(subscription.Node{Type: typ}).UDPSupported() {
			t.Errorf("%q should support udp", typ)
		}
	}

	// Protocols that are not implemented must not claim UDP support.
	for _, typ := range []string{"http", "unknown"} {
		if (subscription.Node{Type: typ}).UDPSupported() {
			t.Errorf("%q should not claim udp support", typ)
		}
	}
}

// startUDPEcho runs a UDP server that echoes datagrams back.
func startUDPEcho(t *testing.T) (addr string, stop func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(buf[:n], from)
		}
	}()
	return conn.LocalAddr().String(), func() { conn.Close() }
}
