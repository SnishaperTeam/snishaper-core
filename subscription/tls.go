package subscription

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// wrapTLS layers TLS over an established tunnel when the node requires it.
// Trojan is always TLS; VMess only when the node sets tls: true.
func wrapTLS(conn net.Conn, node Node, serverName string, alwaysOn bool) (net.Conn, error) {
	if !alwaysOn {
		enabled, _ := strconv.ParseBool(node.Options["tls"])
		if !enabled {
			return conn, nil
		}
	}

	sni := strings.TrimSpace(node.Options["servername"])
	if sni == "" {
		sni = node.ServerName
	}
	if sni == "" {
		sni = serverName
	}
	if sni == "" {
		sni = node.Server
	}
	if sni == "" {
		return nil, fmt.Errorf("tls enabled but no server name available for node %q", node.Name)
	}

	cfg := &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: node.Options["skip-cert-verify"] == "true", //nolint:gosec // mirrors the provider config
	}

	if alpn := node.Options["alpn"]; alpn != "" {
		for _, p := range strings.Split(alpn, ",") {
			if p = strings.TrimSpace(p); p != "" {
				cfg.NextProtos = append(cfg.NextProtos, p)
			}
		}
	}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls handshake with %s failed: %w", sni, err)
	}
	return tlsConn, nil
}
