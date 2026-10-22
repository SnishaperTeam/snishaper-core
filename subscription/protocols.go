package subscription

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
)

// dialSOCKS5 opens a SOCKS5 tunnel to the target.
func dialSOCKS5(serverAddr, username, password, targetHost string, targetPort int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", serverAddr, defaultDialTimeout)
	if err != nil {
		return nil, err
	}
	if err := socks5Negotiate(conn, username, password); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks5Connect(conn, targetHost, targetPort); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func socks5Negotiate(conn net.Conn, username, password string) error {
	methods := []byte{0x00}
	if username != "" {
		methods = []byte{0x00, 0x02}
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return err
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("socks5: unexpected version 0x%02x", reply[0])
	}

	switch reply[1] {
	case 0x00:
		return nil
	case 0x02:
		if username == "" {
			return fmt.Errorf("socks5: server demands credentials but none were provided")
		}
		auth := make([]byte, 0, 3+len(username)+len(password))
		auth = append(auth, 0x01, byte(len(username)))
		auth = append(auth, username...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, password...)
		if _, err := conn.Write(auth); err != nil {
			return err
		}
		authReply := make([]byte, 2)
		if _, err := io.ReadFull(conn, authReply); err != nil {
			return err
		}
		if authReply[1] != 0x00 {
			return fmt.Errorf("socks5: authentication rejected")
		}
		return nil
	default:
		return fmt.Errorf("socks5: no acceptable auth method (server offered 0x%02x)", reply[1])
	}
}

func socks5Connect(conn net.Conn, host string, port int) error {
	if port == 0 {
		port = 443
	}
	addr, err := EncodeSocks5Addr(host, port)
	if err != nil {
		return err
	}
	// A SOCKS5 CONNECT request is VER CMD RSV ATYP ADDR PORT.
	req := append([]byte{0x05, 0x01, 0x00}, addr...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	reply := make([]byte, 3)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("socks5: connect failed with code %d", reply[1])
	}
	// Drain the bound address; VER/REP/RSV were already consumed above.
	_, err = ReadSocks5AddrBody(conn)
	return err
}

// dialHTTPUpstream opens a CONNECT tunnel through an HTTP proxy.
func dialHTTPUpstream(serverAddr, username, password, targetHost string, targetPort int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", serverAddr, defaultDialTimeout)
	if err != nil {
		return nil, err
	}
	if err := httpConnect(conn, targetHost, targetPort, username, password); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func httpConnect(conn net.Conn, targetHost string, targetPort int, username, password string) error {
	if targetPort == 0 {
		targetPort = 443
	}
	target := net.JoinHostPort(targetHost, fmt.Sprint(targetPort))

	var req strings.Builder
	req.WriteString("CONNECT " + target + " HTTP/1.1\r\n")
	req.WriteString("Host: " + target + "\r\n")
	if username != "" {
		req.WriteString("Proxy-Authorization: Basic ")
		req.WriteString(base64.StdEncoding.EncodeToString([]byte(username + ":" + password)))
		req.WriteString("\r\n")
	}
	req.WriteString("\r\n")

	if _, err := conn.Write([]byte(req.String())); err != nil {
		return err
	}

	resp := make([]byte, 0, 512)
	buf := make([]byte, 1)
	for len(resp) < 1024 {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
		resp = append(resp, buf[0])
		if len(resp) >= 4 && string(resp[len(resp)-4:]) == "\r\n\r\n" {
			break
		}
	}

	text := string(resp)
	if !strings.Contains(text, " 200 ") {
		return fmt.Errorf("http proxy CONNECT rejected: %s", firstLineOf(text))
	}
	return nil
}

func firstLineOf(s string) string {
	if idx := strings.Index(s, "\r\n"); idx >= 0 {
		return s[:idx]
	}
	return s
}
