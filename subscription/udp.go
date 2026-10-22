package subscription

import (
	"context"
	"fmt"
	"net"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// ListenPacketUDP opens a UDP tunnel to destination through the node.
//
// The returned conn is a sing N.PacketConn: the datagram destination stays a
// typed M.Socksaddr and buffers move by pointer, matching what sing-tun's
// handler expects. It also satisfies net.PacketConn for callers that need it.
func (n Node) ListenPacketUDP(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	host, port := splitSocksaddr(destination)
	if host == "" || port <= 0 {
		return nil, fmt.Errorf("node %q: invalid udp destination %s", n.Name, destination)
	}
	if n.Port == 0 {
		return nil, fmt.Errorf("node %q has no server port", n.Name)
	}

	// Subscription nodes relay UDP through the Clash core adapters too
	// (mihomo.go).
	if n.Raw != nil {
		return n.listenPacketMihomoUDP(ctx, host, port)
	}

	switch lowerType(n.Type) {
	case "socks5", "socks":
		// The upstream SOCKS5 client implements UDP associate framing and
		// exposes it as a sing PacketConn, so datagrams pass through
		// untouched in both directions.
		client := socks.NewClient(
			N.SystemDialer,
			M.SocksaddrFromNet(resolveUDPAddr(n.Server, n.Port)),
			socks.Version5,
			n.Options["username"],
			n.Options["password"],
		)
		pkt, err := client.ListenPacket(ctx, destination)
		if err != nil {
			return nil, fmt.Errorf("socks5 udp associate: %w", err)
		}
		assoc, ok := pkt.(N.PacketConn)
		if !ok {
			pkt.Close()
			return nil, fmt.Errorf("node %q: socks5 relay is not a sing packet conn", n.Name)
		}
		return assoc, nil

	case "wireguard":
		// The tunnel's own datagram socket carries both directions, so it can
		// be handed to sing-tun directly.
		return n.wgListenPacket(ctx)

	default:
		return nil, fmt.Errorf("node %q: hand-built %s udp relay is no longer supported; import via subscription", n.Name, n.Type)
	}
}

// splitSocksaddr renders a sing Socksaddr as host and port.
func splitSocksaddr(addr M.Socksaddr) (string, int) {
	if addr.IsDomain() {
		return addr.Fqdn, int(addr.Port)
	}
	return addr.Addr.String(), int(addr.Port)
}

// UDPSupported reports whether this node can carry UDP traffic right now.
func (n Node) UDPSupported() bool {
	// Raw nodes ask the mihomo adapter — the core knows per-protocol UDP
	// support (e.g. vmess defaults to udp off unless configured).
	if n.Raw != nil {
		return n.mihomoSupportsUDP()
	}
	switch lowerType(n.Type) {
	case "ss", "ssr", "vmess", "vless", "wireguard", "socks5", "socks", "trojan", "tuic", "hysteria2", "hy2":
		return true
	}
	return false
}

func lowerType(v string) string {
	b := []byte(v)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

func resolveUDPAddr(host string, port int) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return &net.UDPAddr{IP: net.IPv4zero, Port: port}
	}
	return addr
}
