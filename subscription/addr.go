package subscription

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// EncodeSocks5Addr renders an address in the SOCKS5 address format:
// ATYP(1) ADDR DST.PORT. The leading VER/CMD/RSV bytes of a SOCKS5 request are
// not included; callers prepend them.
//
// ATYP 0x01 is IPv4, 0x03 is a domain name, 0x04 is IPv6. Domain names are
// preferred when the host is not a literal IP so the name reaches the proxy
// intact and the exit resolves it.
func EncodeSocks5Addr(host string, port int) ([]byte, error) {
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}

	buf := make([]byte, 0, 1+1+len(host)+2)

	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("host too long: %d", len(host))
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	return append(buf, portBuf[:]...), nil
}

// SplitHostPort is a thin wrapper that tolerates a missing port.
func SplitHostPort(addr string, defaultPort int) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, defaultPort
	}
	return host, port
}

// ReadSocks5Addr parses a complete SOCKS5 address (VER + ATYP + ADDR + PORT).
func ReadSocks5Addr(r io.Reader) (string, error) {
	var ver [1]byte
	if _, err := io.ReadFull(r, ver[:]); err != nil {
		return "", err
	}
	if ver[0] != 0x05 {
		return "", fmt.Errorf("unexpected socks version 0x%02x", ver[0])
	}
	return ReadSocks5AddrBody(r)
}

// ReadSocks5AddrBody parses ATYP + ADDR + PORT, for callers that already
// consumed the VER byte.
func ReadSocks5AddrBody(r io.Reader) (string, error) {
	var head [1]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return "", err
	}

	var host string
	switch head[0] {
	case 0x01:
		var buf [4]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return "", err
		}
		host = net.IP(buf[:]).String()
	case 0x04:
		var buf [16]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return "", err
		}
		host = net.IP(buf[:]).String()
	case 0x03:
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return "", err
		}
		buf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = string(buf)
	default:
		return "", fmt.Errorf("unsupported socks address type 0x%02x", head[0])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf[:])))), nil
}
