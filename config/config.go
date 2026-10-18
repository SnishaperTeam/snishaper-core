// Package config holds configuration types and small network helpers shared
// by several snishaper-core packages (proxy, dohresolver, singtun, cfpool,
// certmanager). Keeping them in this leaf package avoids import cycles
// between the consumers.
package config

import (
	"net"
	"strings"
)

// CertVerifyConfig describes how the TLS certificate of an upstream or DoH
// node is verified. The zero value means "default verification".
type CertVerifyConfig struct {
	Mode                  string   `json:"mode,omitempty"`
	Names                 []string `json:"names,omitempty"`
	Suffixes              []string `json:"suffixes,omitempty"`
	SPKISHA256            []string `json:"spki_sha256,omitempty"`
	AllowUnknownAuthority bool     `json:"allow_unknown_authority,omitempty"`
}

// IsZero reports whether no verification option is set.
func (c CertVerifyConfig) IsZero() bool {
	return strings.TrimSpace(c.Mode) == "" &&
		len(c.Names) == 0 &&
		len(c.Suffixes) == 0 &&
		len(c.SPKISHA256) == 0 &&
		!c.AllowUnknownAuthority
}

// MapNAT64Addr maps an IPv4 address into the given NAT64 prefix. An empty
// prefix or an unparseable input returns the input unchanged. The second
// return value reports whether the input was an IPv4 address.
func MapNAT64Addr(ipStr string, prefix string) (string, bool) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return ipStr, true
	}
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return ipStr, true
	}
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return ipStr, false
	}

	var prefixIP net.IP
	if strings.Contains(prefix, "/") {
		_, ipnet, err := net.ParseCIDR(prefix)
		if err == nil && ipnet != nil {
			prefixIP = ipnet.IP
		}
	} else {
		prefixIP = net.ParseIP(prefix)
	}

	if prefixIP == nil || len(prefixIP) != 16 {
		return ipStr, true
	}
	mappedIP := make(net.IP, 16)
	copy(mappedIP, prefixIP[:12])
	copy(mappedIP[12:], ipv4)
	return mappedIP.String(), true
}

// HalfClose closes the write side of conn, keeping the read side open so a
// peer can still flush its half of the conversation. Conns that cannot
// half-close are closed entirely.
func HalfClose(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	conn.Close()
}
