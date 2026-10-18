package subscription

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// VLESS is a lightweight protocol: TLS carries the traffic, the request is a
// 16-byte header (version, UUID, addons, command, port, address type, address)
// and the reply is a 2-byte header. Unlike VMess it adds no encryption of its
// own, which is why it is almost always used with TLS or REALITY.
type vlessDialer struct {
	uuid     [16]byte
	security string
	network  string
	path     string
	host     string
}

// dialVLessOn performs the VLESS handshake over an established transport.
func dialVLessOn(conn net.Conn, node Node, targetHost string, targetPort int) (net.Conn, error) {
	uuid, err := parseUUID(node.Options["uuid"])
	if err != nil {
		return nil, err
	}

	network := strings.ToLower(strings.TrimSpace(node.Options["network"]))
	if network == "" {
		network = "tcp"
	}
	path := node.Options["path"]
	if path == "" {
		path = "/"
	}
	host := node.Options["host"]

	// WebSocket transport: the VLESS header rides in the request body after an
	// HTTP Upgrade handshake.
	if network == "ws" || network == "websocket" {
		return dialVLessWebsocket(conn, node, uuid, targetHost, targetPort, path, host)
	}

	// Raw TCP: header then bidirectional stream.
	if network != "tcp" && network != "" {
		return nil, fmt.Errorf("vless: unsupported transport %q", network)
	}

	header, err := buildVLESSHeader(uuid, 0x01, targetHost, targetPort)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(header); err != nil {
		return nil, err
	}

	// The server replies with a 2-byte version/response header.
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, fmt.Errorf("vless: reading response header: %w", err)
	}
	if reply[0] != 0x00 {
		return nil, fmt.Errorf("vless: unexpected response version %d", reply[0])
	}

	return conn, nil
}

// buildVLESSHeader assembles the 16+ byte request header.
func buildVLESSHeader(uuid [16]byte, command byte, host string, port int) ([]byte, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("vless: invalid port %d", port)
	}

	buf := make([]byte, 0, 24+len(host))
	buf = append(buf, 0x00) // version
	buf = append(buf, uuid[:]...)
	buf = append(buf, 0x00) // addons length

	// Command: 0x01 TCP, 0x02 UDP over the same stream.
	buf = append(buf, command)

	// Port, big endian.
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	buf = append(buf, portBuf[:]...)

	// Address type follows the VLESS/sing convention: 0x01 IPv4, 0x02 domain,
	// 0x03 IPv6 (see sing's metadata.MetadataType constants).
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 0x03)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("vless: host too long: %d", len(host))
		}
		buf = append(buf, 0x02, byte(len(host)))
		buf = append(buf, host...)
	}

	return buf, nil
}

// upgradeWebsocket performs the RFC 6455 handshake and returns a framed
// connection. The caller writes whatever protocol header follows.
func upgradeWebsocket(conn net.Conn, path, host string) (*websocketConn, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	// RFC 6455 requires the base64 nonce to decode to 16 bytes.
	wsKey := base64Encode(key)

	var req strings.Builder
	req.WriteString("GET " + path + " HTTP/1.1\r\n")
	req.WriteString("Host: " + host + "\r\n")
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	req.WriteString("Sec-WebSocket-Key: " + wsKey + "\r\n")
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	req.WriteString("\r\n")

	if _, err := conn.Write([]byte(req.String())); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		return nil, fmt.Errorf("vless: websocket upgrade: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("vless: websocket upgrade rejected with status %d", resp.StatusCode)
	}

	return &websocketConn{
		Conn:   conn,
		reader: reader,
		// Client frames must be masked.
		mask: true,
	}, nil
}

// dialVLessWebsocket performs the WebSocket upgrade then writes the header as
// the first websocket frame.
func dialVLessWebsocket(conn net.Conn, node Node, uuid [16]byte, targetHost string, targetPort int, path, host string) (net.Conn, error) {
	ws, err := upgradeWebsocket(conn, path, hostOr(host, targetHost))
	if err != nil {
		return nil, err
	}

	header, err := buildVLESSHeader(uuid, 0x01, targetHost, targetPort)
	if err != nil {
		ws.Close()
		return nil, err
	}
	if err := ws.WriteBinary(header); err != nil {
		ws.Close()
		return nil, err
	}

	// Read the 2-byte VLESS response from the first binary frame. Any payload
	// after it belongs to the stream, so keep it for the next read.
	reply, err := ws.ReadBinary()
	if err != nil {
		ws.Close()
		return nil, fmt.Errorf("vless: reading websocket response: %w", err)
	}
	if len(reply) < 2 || reply[0] != 0x00 {
		ws.Close()
		return nil, fmt.Errorf("vless: unexpected websocket response")
	}
	if len(reply) > 2 {
		ws.fragment = reply[2:]
	}

	return ws, nil
}

func hostOr(candidates ...string) string {
	for _, c := range candidates {
		if c = strings.TrimSpace(c); c != "" {
			return c
		}
	}
	return ""
}

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func base64Encode(b []byte) string {
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		out.WriteByte(base64Alphabet[chunk[0]>>2])
		out.WriteByte(base64Alphabet[(chunk[0]&0x03)<<4|chunk[1]>>4])
		if n > 1 {
			out.WriteByte(base64Alphabet[(chunk[1]&0x0f)<<2|chunk[2]>>6])
		} else {
			out.WriteByte('=')
		}
		if n > 2 {
			out.WriteByte(base64Alphabet[chunk[2]&0x3f])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}
