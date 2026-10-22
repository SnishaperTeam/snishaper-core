package subscription

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// defaultDialTimeout bounds a single dial attempt.
const defaultDialTimeout = 10 * time.Second

// DialTimeout opens a tunnel to targetHost:targetPort through the given node.
//
// It returns a net.Conn that carries the tunnelled byte stream; the caller
// speaks the application protocol (TLS, HTTP, ...) over it as usual.
func (n Node) DialTimeout(targetHost string, targetPort int, timeout time.Duration) (net.Conn, error) {
	if strings.TrimSpace(n.Type) == "" {
		return nil, fmt.Errorf("node %q has no protocol type", n.Name)
	}
	if n.Port == 0 {
		return nil, fmt.Errorf("node %q has no server port", n.Name)
	}
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}

	// Subscription nodes carry their raw Clash config and dial through the
	// Clash core adapters (mihomo.go) — the only supported path, covering
	// every protocol the core can parse (vmess/vless/trojan/ss/tuic/
	// hysteria2, ws/grpc transports, REALITY, ...).
	if n.Raw != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return n.dialMihomoTCP(ctx, targetHost, targetPort)
	}

	serverAddr := net.JoinHostPort(n.Server, fmt.Sprint(n.Port))

	// Hand-built nodes without raw config keep the small standard-protocol
	// dialers below; the hand-rolled crypto protocol stack was removed.
	switch strings.ToLower(strings.TrimSpace(n.Type)) {
	case "wireguard":
		// WireGuard is a layer 3 tunnel: the user space stack dials the target
		// by address once the tunnel is up.
		return n.wgDialTCP(targetHost, targetPort)

	case "socks5":
		username := n.Options["username"]
		password := n.Options["password"]
		return dialSOCKS5(serverAddr, username, password, targetHost, targetPort)

	case "http", "https":
		username := n.Options["username"]
		password := n.Options["password"]
		return dialHTTPUpstream(serverAddr, username, password, targetHost, targetPort)

	default:
		return nil, fmt.Errorf("node %q: hand-built %s nodes are no longer supported; import via subscription", n.Name, n.Type)
	}
}

// Dial is DialTimeout with the default timeout.
func (n Node) Dial(targetHost string, targetPort int) (net.Conn, error) {
	return n.DialTimeout(targetHost, targetPort, defaultDialTimeout)
}

// Supported reports whether this node's protocol can be dialled.
func (n Node) Supported() bool {
	// Raw nodes are dialled through the mihomo adapters, which support every
	// protocol the core can parse — far beyond the legacy whitelist below.
	if n.Raw != nil {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(n.Type)) {
	case "ss", "ssr", "vmess", "vless", "trojan", "tuic", "hysteria2", "hy2", "wireguard", "socks5", "http", "https":
		return true
	}
	return false
}
