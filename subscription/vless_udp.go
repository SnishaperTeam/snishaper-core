package subscription

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// vlessUDPPacketConn relays datagrams over VLESS using the protocol's plain
// packet mode: one bidirectional stream per datagram, opened with command
// 0x02.
//
//	stream: [version][uuid][addons][0x02][port][type][addr][payload]
//	reply:  [version][addons][payload]
//
// The request header and the datagram are written as one unit because a server
// cannot answer before it has seen both.
type vlessUDPPacketConn struct {
	node    Node
	uuid    [16]byte
	network string
	path    string
	host    string

	// pending holds a payload that arrived before the caller read it.
	mu      sync.Mutex
	pending []byte
	source  M.Socksaddr
	closed  bool
}

func dialVLessUDP(node Node) (*vlessUDPPacketConn, error) {
	uuid, err := parseUUID(node.Options["uuid"])
	if err != nil {
		return nil, err
	}
	if node.Port == 0 {
		return nil, fmt.Errorf("vless: node %q has no server port", node.Name)
	}

	network := strings.ToLower(strings.TrimSpace(node.Options["network"]))
	if network == "" {
		network = "tcp"
	}
	path := node.Options["path"]
	if path == "" {
		path = "/"
	}

	return &vlessUDPPacketConn{
		node:    node,
		uuid:    uuid,
		network: network,
		path:    path,
		host:    node.Options["host"],
	}, nil
}

// openStream establishes a stream to the server, writes the request frame for
// destination together with payload, and consumes the reply header so the
// caller reads only the response body.
func (c *vlessUDPPacketConn) openStream(destination M.Socksaddr, payload []byte) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp",
		net.JoinHostPort(c.node.Server, strconv.Itoa(c.node.Port)), defaultDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("vless udp: dialing the server failed: %w", err)
	}

	// Present the configured SNI, falling back to the node's own server
	// address (wrapTLS resolves the full chain: servername option ->
	// ServerName field -> server address).
	secure, err := wrapTLS(raw, c.node, "", c.node.Options["tls"] == "true")
	if err != nil {
		return nil, err
	}

	host, port := singAddrHostPort(destination)
	header, err := buildVLESSHeader(c.uuid, 0x02, host, port)
	if err != nil {
		secure.Close()
		return nil, err
	}

	frame := make([]byte, 0, len(header)+len(payload))
	frame = append(frame, header...)
	frame = append(frame, payload...)

	var conn net.Conn = secure
	if c.network == "ws" || c.network == "websocket" {
		ws, err := c.dialWebsocketStream(secure, frame)
		if err != nil {
			secure.Close()
			return nil, err
		}
		conn = ws
	} else {
		_ = secure.SetWriteDeadline(time.Now().Add(defaultDialTimeout))
		if _, err := secure.Write(frame); err != nil {
			secure.Close()
			return nil, fmt.Errorf("vless udp: writing the request failed: %w", err)
		}
	}

	// The reply starts with the two byte version/addons header.
	reply := make([]byte, 2)
	_ = conn.SetReadDeadline(time.Now().Add(defaultDialTimeout))
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless udp: reading the reply header failed: %w", err)
	}
	if reply[0] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("vless udp: unexpected reply version %d", reply[0])
	}

	return conn, nil
}

// dialWebsocketStream performs the upgrade and sends the frame as the first
// binary message.
func (c *vlessUDPPacketConn) dialWebsocketStream(secure net.Conn, frame []byte) (net.Conn, error) {
	ws, err := upgradeWebsocket(secure, c.path, hostOr(c.host, c.node.Server))
	if err != nil {
		return nil, err
	}
	if err := ws.WriteBinary(frame); err != nil {
		ws.Close()
		return nil, err
	}
	return ws, nil
}

func (c *vlessUDPPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	payload := append([]byte(nil), buffer.Bytes()...)
	buffer.Release()

	conn, err := c.openStream(destination, payload)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(defaultDialTimeout))
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("vless udp reading the reply failed: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.pending = append(c.pending, reply...)
	c.source = destination
	return nil
}

func (c *vlessUDPPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.pending) == 0 {
		if c.closed {
			return M.Socksaddr{}, net.ErrClosed
		}
		// Plain mode has no server-initiated datagrams, so a read only succeeds
		// once WritePacket has completed its round trip.
		return M.Socksaddr{}, io.EOF
	}

	buffer.Write(c.pending)
	source := c.source
	c.pending = nil
	return source, nil
}

// singAddrHostPort renders a sing address as host and port.
func singAddrHostPort(addr M.Socksaddr) (string, int) {
	if addr.IsDomain() {
		return addr.Fqdn, int(addr.Port)
	}
	return addr.Addr.String(), int(addr.Port)
}

func (c *vlessUDPPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.pending = nil
	return nil
}

// The underlying streams are per-datagram, so the deadline setters are no-ops.
func (c *vlessUDPPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (c *vlessUDPPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *vlessUDPPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *vlessUDPPacketConn) SetWriteDeadline(t time.Time) error { return nil }
