package subscription

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// parseUUID decodes a VMess UUID into its 16 raw bytes.
func parseUUID(raw string) ([16]byte, error) {
	var id [16]byte
	cleaned := strings.ReplaceAll(strings.TrimSpace(raw), "-", "")
	if len(cleaned) != 32 {
		return id, fmt.Errorf("invalid uuid length %d", len(cleaned))
	}
	for i := 0; i < 16; i++ {
		hi, err := hexVal(cleaned[i*2])
		if err != nil {
			return id, err
		}
		lo, err := hexVal(cleaned[i*2+1])
		if err != nil {
			return id, err
		}
		id[i] = hi<<4 | lo
	}
	return id, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid hex digit %q", string(c))
}

// dialVMessOn performs the VMess AEAD handshake over an established transport.
// The caller decides whether that transport is already TLS-wrapped.
func dialVMessOn(conn net.Conn, node Node, targetHost string, targetPort int) (net.Conn, error) {
	uuid, err := parseUUID(node.Options["uuid"])
	if err != nil {
		return nil, err
	}

	security := strings.ToLower(strings.TrimSpace(node.Options["method"]))
	if security == "" {
		security = strings.ToLower(strings.TrimSpace(node.Options["cipher"]))
	}
	if security == "" {
		security = "auto"
	}
	switch security {
	case "auto", "none", "zero", "aes-128-gcm":
	default:
		return nil, fmt.Errorf("unsupported vmess security %q", security)
	}

	if targetPort == 0 {
		return nil, fmt.Errorf("vmess requires a target port")
	}

	if err := vmessHandshake(conn, uuid, node.Name, targetHost, targetPort, security); err != nil {
		return nil, err
	}
	return conn, nil
}

func vmessSecurityByte(security string) byte {
	if security == "aes-128-gcm" {
		return 0x03
	}
	return 0x01
}

func vmessHandshake(conn net.Conn, uuid [16]byte, sni, targetHost string, targetPort int, security string) error {
	// The AEAD key is always 32 bytes: the UUID for "auto"/"none", or the
	// first 16 bytes of SHA-256(uuid) for AES-128-GCM compatibility. ChaCha20
	// requires the full 32 bytes, so zero-pad the derived key.
	var key [32]byte
	if security == "aes-128-gcm" {
		sum := sha256.Sum256(uuid[:])
		copy(key[:16], sum[:16])
	} else {
		copy(key[:16], uuid[:])
	}

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return err
	}

	var authID [16]byte
	if _, err := rand.Read(authID[:]); err != nil {
		return err
	}

	// The payload carries the command (TCP connect) plus the SOCKS5-style
	// target address.
	addr, err := EncodeSocks5Addr(targetHost, targetPort)
	if err != nil {
		return err
	}
	payload := make([]byte, 0, 1+2+len(addr)+4)
	payload = append(payload, 0x01) // TCP
	payload = append(payload, byte(len(addr)>>8), byte(len(addr)))
	payload = append(payload, addr...)
	payload = append(payload, 0, 0, 0, 0) // reserved

	var padding [1]byte
	pad := make([]byte, 8)
	if _, err := rand.Read(pad); err != nil {
		return err
	}
	padding[0] = byte(len(pad))

	// body: version(1) + requestIV(16) + requestHeader + padding + auth
	header := make([]byte, 0, 1+1+len(sni))
	header = append(header, vmessSecurityByte(security))
	header = append(header, byte(len(sni)))
	header = append(header, sni...)
	header = append(header, byte(len(pad)))
	header = append(header, pad...)

	body := make([]byte, 0, 1+16+len(header)+16)
	body = append(body, 0x01) // version
	body = append(body, authID[:]...)
	body = append(body, header...)
	body = append(body, authID[:]...) // auth for AEAD-2022 style validation
	body = append(body, byte(len(payload)>>8), byte(len(payload)))
	body = append(body, payload...)

	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}

	sealed := aead.Seal(nil, nonce[:], body, nil)

	out := make([]byte, 0, 2+16+len(sealed))
	out = append(out, byte(len(sealed)>>8), byte(len(sealed)))
	out = append(out, authID[:]...)
	out = append(out, sealed...)
	out = append(out, nonce[:]...)

	if _, err := conn.Write(out); err != nil {
		return err
	}

	// The server answers with a 4-byte response header whose first byte must
	// echo the UUID, confirming the auth key was accepted.
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != uuid[0] {
		return fmt.Errorf("vmess: response auth id mismatch")
	}
	return nil
}

// dialTrojan performs the Trojan handshake on an already-established
// transport. Trojan always runs over TLS, so conn must already be encrypted;
// the caller is responsible for the upgrade.
func dialTrojan(conn net.Conn, node Node, targetHost string, targetPort int) (net.Conn, error) {
	password := node.Options["password"]
	if password == "" {
		return nil, fmt.Errorf("trojan password is required")
	}
	if targetPort == 0 {
		return nil, fmt.Errorf("trojan requires a target port")
	}

	// Trojan hashes the password with SHA-224 and sends it lowercase hex.
	sum := sha256.Sum224([]byte(password))
	hexHash := fmt.Sprintf("%x", sum)

	addr, err := EncodeSocks5Addr(targetHost, targetPort)
	if err != nil {
		return nil, err
	}

	payload := make([]byte, 0, len(hexHash)+4+len(addr))
	payload = append(payload, hexHash...)
	payload = append(payload, 0x0d, 0x0a) // CRLF
	payload = append(payload, trojanCommandTCP)
	payload = append(payload, addr...)
	payload = append(payload, 0x0d, 0x0a) // CRLF

	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	return conn, nil
}

// Trojan command bytes. The server dispatches on this byte, so it must be
// present between the CRLF and the destination address.
const (
	trojanCommandTCP byte = 0x01
	trojanCommandUDP byte = 0x03
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

var _ = binary.BigEndian
var _ cipher.AEAD
var _ = time.Now
