package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/SnishaperTeam/snishaper-core/subscription"
)

// subscriptionDialer resolves the proxy node bound to a rule and tunnels the
// connection through it. It is attached to the ProxyServer so a subscription
// can carry real traffic instead of only reshaping the rule set.
type subscriptionDialer struct {
	mu    sync.RWMutex
	store *subscription.Store
}

// SetSubscriptionDialer wires the dialer to a subscription store.
func (p *ProxyServer) SetSubscriptionDialer(store *subscription.Store) {
	p.subscriptionDialer = &subscriptionDialer{store: store}
}

func (p *ProxyServer) subscriptionDialerForTarget(targetAddr string) *subscriptionDialer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.subscriptionDialer
}

// OpenUDP implements singtun.UDPRelay. It returns ok=false when no node is
// bound, so the TUN layer falls back to a direct socket.
func (p *ProxyServer) OpenUDP(ctx context.Context, destination M.Socksaddr) (N.PacketConn, bool, error) {
	dialer := p.subscriptionDialerForTarget("")
	if dialer == nil {
		return nil, false, nil
	}

	node, ok := dialer.nodeForGroup("")
	if !ok || !node.UDPSupported() {
		return nil, false, nil
	}

	pkt, err := node.ListenPacketUDP(ctx, destination)
	if err != nil {
		return nil, true, err
	}

	host, port := subscription.SplitHostPort(destination.String(), 0)
	p.tracef("[Subscription] udp relay %s:%d via node %s (%s)", host, port, node.Name, node.Type)
	return pkt, true, nil
}

// nodeForGroup resolves the node chosen for the group that owns the target.
// A subscription may declare several groups; the first group that contains a
// usable selection wins, which matches how Clash treats a single active group.
func (d *subscriptionDialer) nodeForGroup(targetAddr string) (subscription.Node, bool) {
	if d == nil || d.store == nil {
		return subscription.Node{}, false
	}

	entry := d.store.ActiveEntry()
	if entry == nil || entry.Builtin || len(entry.Nodes) == 0 {
		return subscription.Node{}, false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, group := range entry.Groups {
		selected := entry.Selection[group.Name]
		if selected == "" {
			continue
		}
		for _, n := range entry.Nodes {
			if n.Name == selected && n.Supported() {
				return n, true
			}
		}
	}
	return subscription.Node{}, false
}

// dialThroughSubscription opens a tunnel to targetAddr through the node bound
// to the active subscription. It reports false when no node applies, so the
// caller can fall back to the direct path.
func (p *ProxyServer) dialThroughSubscription(targetAddr string) (net.Conn, bool, error) {
	dialer := p.subscriptionDialerForTarget(targetAddr)
	if dialer == nil {
		return nil, false, nil
	}

	node, ok := dialer.nodeForGroup(targetAddr)
	if !ok {
		return nil, false, nil
	}

	host, port := subscription.SplitHostPort(targetAddr, 0)
	if host == "" {
		host = targetAddr
		port = 443
	}

	conn, err := node.Dial(host, port)
	if err != nil {
		return nil, true, fmt.Errorf("subscription node %q: %w", node.Name, err)
	}

	// The node tunnel carries the raw byte stream; the caller layers its own
	// TLS/ECH handling on top when the rule requires it.
	p.tracef("[Subscription] tunnelled %s via node %s (%s)", targetAddr, node.Name, node.Type)
	return conn, true, nil
}

// secureOverTunnel negotiates TLS for the real target on top of a subscription
// tunnel, reusing the proxy's uTLS/ECH machinery so ECH and fragmentation rules
// keep working. The returned conn is ready for the upper layers to speak over.
func (p *ProxyServer) secureOverTunnel(tunnel net.Conn, cr *connectResult) (net.Conn, error) {
	host := cr.targetHost
	if host == "" {
		h, _ := subscription.SplitHostPort(cr.targetAddr, 0)
		host = h
	}

	// transparent mode forwards raw bytes; the caller terminates TLS.
	if cr.effectiveMode == "transparent" {
		return tunnel, nil
	}

	var echBytes []byte
	if cr.rule.ECHEnabled {
		echBytes = p.resolveRuleECHConfig(host, cr.rule)
	}
	allowInsecure := len(echBytes) == 0

	// The MITM relay speaks whatever it negotiated with the CLIENT over the
	// fake-cert session, and pipes those bytes into the upstream verbatim.
	// GetUConn offers h2 by default and a preset uTLS ClientHello does not
	// surface the negotiated ALPN through ConnectionState(), so the relay
	// cannot detect an h2 upstream — force http/1.1 here so both sides of the
	// relay agree (the non-tunnelled path achieves the same via initialALPN).
	alpn := ""
	if cr.effectiveMode == "mitm" {
		alpn = "http/1.1"
	}

	uconn := p.GetUConn(tunnel, cr.rule.SniFake, host, cr.rule, allowInsecure, alpn, echBytes)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := uconn.HandshakeContext(ctx); err != nil {
		tunnel.Close()
		return nil, fmt.Errorf("tls handshake through subscription node for %s: %w", host, err)
	}
	return uconn, nil
}

// subscriptionTargetHost extracts a hostname for dialing, preferring the
// literal address.
func subscriptionTargetHost(targetAddr string) (string, int) {
	host, port := subscription.SplitHostPort(targetAddr, 443)
	return strings.TrimSpace(host), port
}
