package subscription

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

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
	// Clash core adapters (mihomo.go) — the hand-rolled switch below proved
	// unable to speak modern node configs (vmess ws/grpc, REALITY, ...) and
	// stayed only for nodes built without raw config.
	if n.Raw != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return n.dialMihomoTCP(ctx, targetHost, targetPort)
	}

	serverAddr := net.JoinHostPort(n.Server, fmt.Sprint(n.Port))

	switch strings.ToLower(strings.TrimSpace(n.Type)) {
	case "ss", "ssr":
		cipherName := n.Options["cipher"]
		if cipherName == "" {
			cipherName = n.Options["method"]
		}
		conn, err := dialShadowsocks(cipherName, n.Options["password"], serverAddr, "tcp")
		if err != nil {
			return nil, err
		}
		addr, err := EncodeSocks5Addr(targetHost, targetPort)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := conn.Write(addr); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil

	case "vmess":
		// When TLS is configured the AEAD header must travel inside the
		// encrypted channel, so upgrade before handshaking. The handshake
		// terminates at the node's own server, so the SNI fallback chain must
		// never use the tunnel target: Clash-style configs omit servername
		// when it equals the server address, and sending the target domain
		// instead fails the handshake (and leaks the target).
		raw, err := net.DialTimeout("tcp", serverAddr, timeout)
		if err != nil {
			return nil, err
		}
		secure, err := wrapTLS(raw, n, "", false)
		if err != nil {
			return nil, err
		}
		return dialVMessOn(secure, n, targetHost, targetPort)

	case "vless":
		// VLESS carries no encryption of its own, so TLS (or REALITY) is
		// mandatory in practice; upgrade before sending the request header.
		raw, err := net.DialTimeout("tcp", serverAddr, timeout)
		if err != nil {
			return nil, err
		}
		secure, err := wrapTLS(raw, n, "", false)
		if err != nil {
			return nil, err
		}
		return dialVLessOn(secure, n, targetHost, targetPort)

	case "trojan":
		// Trojan always runs over TLS: upgrade first, then send the password
		// exchange inside the encrypted channel.
		raw, err := net.DialTimeout("tcp", serverAddr, timeout)
		if err != nil {
			return nil, err
		}
		secure, err := wrapTLS(raw, n, "", true)
		if err != nil {
			return nil, err
		}
		return dialTrojan(secure, n, targetHost, targetPort)

	case "hysteria2", "hy2":
		// Hysteria 2 authenticates over HTTP/3 and then relays over the same
		// QUIC connection.
		dialCtx, cancelDial := context.WithTimeout(context.Background(), timeout)
		defer cancelDial()
		session, err := dialHysteria(dialCtx, n)
		if err != nil {
			return nil, err
		}
		streamConn, err := session.dialTCP(dialCtx, targetHost, targetPort)
		if err != nil {
			session.close()
			return nil, err
		}
		return streamConn, nil

	case "wireguard":
		// WireGuard is a layer 3 tunnel: the user space stack dials the target
		// by address once the tunnel is up.
		return n.wgDialTCP(targetHost, targetPort)

	case "tuic":
		// TUIC v5 multiplexes everything over one QUIC connection: TCP uses a
		// bidirectional stream, UDP uses datagrams.
		dialCtx, cancelDial := context.WithTimeout(context.Background(), timeout)
		defer cancelDial()
		tc, err := dialTUIC(dialCtx, n)
		if err != nil {
			return nil, err
		}
		streamConn, err := tc.dialTCP(dialCtx, targetHost, targetPort)
		if err != nil {
			tc.close()
			return nil, err
		}
		return &tuicSessionConn{Conn: streamConn, session: tc}, nil

	case "socks5":
		username := n.Options["username"]
		password := n.Options["password"]
		return dialSOCKS5(serverAddr, username, password, targetHost, targetPort)

	case "http", "https":
		username := n.Options["username"]
		password := n.Options["password"]
		return dialHTTPUpstream(serverAddr, username, password, targetHost, targetPort)

	default:
		return nil, fmt.Errorf("unsupported proxy protocol %q for node %q", n.Type, n.Name)
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
