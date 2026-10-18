package subscription

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// XUDP status bits carried in the status byte of every frame. The low nibble
// describes the session state, the upper bits carry option flags.
const (
	xudpStatusNew  byte = 0x01
	xudpStatusKeep byte = 0x02
	xudpStatusEnd  byte = 0x04

	// xudpStatusData marks a frame that carries payload rather than only
	// opening or closing a session.
	xudpStatusData byte = 0x08
)

// vmessUDPPacketConn tunnels datagrams over a single VMess connection using the
// XUDP encoding. Every packet is framed as:
//
//	[2 bytes session id][1 byte status][1 byte padding length][address]
//	[2 bytes payload length][payload][padding]
//
// The session id stays fixed for the life of the connection: the first frame
// announces it with the NEW bit and later frames reuse it. The connection
// address carries the magic domain, so the server knows to demultiplex rather
// than dial a literal destination.
type vmessUDPPacketConn struct {
	node Node
	uuid [16]byte
	// security is the cipher the VMess header negotiated.
	security string

	conn    net.Conn
	session uint16

	// pending holds a payload that arrived before the caller read it.
	mu      sync.Mutex
	pending []byte
	source  M.Socksaddr
	closed  bool
}

// xudpMagicDomain tells the server to treat the stream as XUDP.
const xudpMagicDomain = "sp.packet-addr.v2fly.arpa"

func dialVMessUDP(node Node) (*vmessUDPPacketConn, error) {
	uuid, err := parseUUID(node.Options["uuid"])
	if err != nil {
		return nil, err
	}
	if node.Port == 0 {
		return nil, fmt.Errorf("vmess: node %q has no server port", node.Name)
	}

	security := node.Options["method"]
	if security == "" {
		security = node.Options["cipher"]
	}
	if security == "" {
		security = "auto"
	}
	switch security {
	case "auto", "none", "zero", "aes-128-gcm":
	default:
		return nil, fmt.Errorf("vmess: unsupported security %q", security)
	}

	return &vmessUDPPacketConn{
		node:     node,
		uuid:     uuid,
		security: security,
	}, nil
}

// connect establishes the VMess connection and opens the XUDP session.
func (c *vmessUDPPacketConn) connect() (net.Conn, error) {
	if c.conn != nil {
		return c.conn, nil
	}

	serverAddr := net.JoinHostPort(c.node.Server, fmt.Sprint(c.node.Port))
	raw, err := net.DialTimeout("tcp", serverAddr, defaultDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("vmess udp: dialing the server failed: %w", err)
	}

	secure, err := wrapTLS(raw, c.node, "", c.node.Options["tls"] == "true")
	if err != nil {
		return nil, err
	}

	// The handshake target is the magic domain, so the server sets up XUDP
	// demultiplexing instead of dialling a real destination.
	tunnelled, err := dialVMessOn(secure, c.node, xudpMagicDomain, 0)
	if err != nil {
		secure.Close()
		return nil, err
	}

	c.conn = tunnelled
	return secure, nil
}

// WritePacket frames one datagram and sends it over the shared connection.
func (c *vmessUDPPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	payload := append([]byte(nil), buffer.Bytes()...)
	buffer.Release()

	conn, err := c.connect()
	if err != nil {
		return err
	}

	c.mu.Lock()
	frame := buildXUDPFrame(c.session, xudpStatusData, destination, payload, nil)
	c.mu.Unlock()

	_ = conn.SetWriteDeadline(time.Now().Add(defaultDialTimeout))
	if _, err := conn.Write(frame); err != nil {
		c.resetConn()
		return fmt.Errorf("vmess udp write failed: %w", err)
	}
	return nil
}

// ReadPacket reads the next framed datagram.
func (c *vmessUDPPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return M.Socksaddr{}, net.ErrClosed
		}
		conn := c.conn
		c.mu.Unlock()

		if conn == nil {
			return M.Socksaddr{}, io.EOF
		}

		_ = conn.SetReadDeadline(time.Now().Add(defaultDialTimeout))
		payload, source, status, err := readXUDPFrame(conn)
		if err != nil {
			c.resetConn()
			return M.Socksaddr{}, err
		}

		if status&xudpStatusEnd != 0 {
			c.resetConn()
			return M.Socksaddr{}, io.EOF
		}
		if len(payload) == 0 {
			// A control frame with no payload; wait for the next one.
			continue
		}

		buffer.Write(payload)

		c.mu.Lock()
		c.source = source
		c.mu.Unlock()
		return source, nil
	}
}

func (c *vmessUDPPacketConn) resetConn() {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// buildXUDPFrame renders one XUDP packet. The address is always present so the
// layout stays strictly positional; control frames simply carry a zero length
// payload.
func buildXUDPFrame(sessionID uint16, status byte, destination M.Socksaddr, payload, padding []byte) []byte {
	frame := make([]byte, 0, 8+len(payload)+len(padding))

	var sid [2]byte
	sid[0] = byte(sessionID >> 8)
	sid[1] = byte(sessionID)
	frame = append(frame, sid[:]...)
	frame = append(frame, status)
	frame = append(frame, byte(len(padding)))

	// Serialize the destination with sing's writer so domains keep their type
	// on the wire.
	addrWriter := buf.NewSize(M.SocksaddrSerializer.AddrPortLen(destination) + 4)
	if err := M.SocksaddrSerializer.WriteAddrPort(addrWriter, destination); err == nil {
		frame = append(frame, addrWriter.Bytes()...)
	}
	addrWriter.Release()

	var length [2]byte
	length[0] = byte(len(payload) >> 8)
	length[1] = byte(len(payload))
	frame = append(frame, length[:]...)
	frame = append(frame, payload...)
	return append(frame, padding...)
}

// readXUDPFrame decodes one packet from the stream. Every frame carries an
// address, including control frames, so the layout is strictly positional and
// no lookahead is needed.
func readXUDPFrame(r io.Reader) (payload []byte, source M.Socksaddr, status byte, err error) {
	// Fixed part: session id(2), status(1), padding length(1). The address
	// type follows immediately after these four bytes.
	var head [4]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return nil, M.Socksaddr{}, 0, err
	}
	status = head[2]
	paddingLen := int(head[3])

	destination, _, err := readSocksAddrLen(r)
	if err != nil {
		return nil, M.Socksaddr{}, 0, err
	}

	var lengthBuf [2]byte
	if _, err = io.ReadFull(r, lengthBuf[:]); err != nil {
		return nil, M.Socksaddr{}, 0, err
	}
	length := int(lengthBuf[0])<<8 | int(lengthBuf[1])

	if length > 0 {
		payload = make([]byte, length)
		if _, err = io.ReadFull(r, payload); err != nil {
			return nil, M.Socksaddr{}, 0, err
		}
	}

	if paddingLen > 0 {
		if _, err = io.ReadFull(r, make([]byte, paddingLen)); err != nil {
			return nil, M.Socksaddr{}, 0, err
		}
	}

	return payload, destination, status, nil
}

// readSocksAddrLen reads a SOCKS5 style address and reports its length.
func readSocksAddrLen(r io.Reader) (M.Socksaddr, int, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return M.Socksaddr{}, 0, err
	}

	var host string
	var offset int

	switch atyp[0] {
	case 0x01:
		var buf4 [4]byte
		if _, err := io.ReadFull(r, buf4[:]); err != nil {
			return M.Socksaddr{}, 0, err
		}
		host = net.IP(buf4[:]).String()
		offset = 1 + 4
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return M.Socksaddr{}, 0, err
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return M.Socksaddr{}, 0, err
		}
		host = string(name)
		offset = 1 + 1 + int(l[0])
	case 0x04:
		var buf16 [16]byte
		if _, err := io.ReadFull(r, buf16[:]); err != nil {
			return M.Socksaddr{}, 0, err
		}
		host = net.IP(buf16[:]).String()
		offset = 1 + 16
	default:
		return M.Socksaddr{}, 0, fmt.Errorf("xudp: unsupported address type 0x%02x", atyp[0])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return M.Socksaddr{}, 0, err
	}
	port := uint16(portBuf[0])<<8 | uint16(portBuf[1])
	offset += 2

	if ip := net.ParseIP(host); ip != nil {
		return M.Socksaddr{Addr: ipAddr(ip), Port: port}, offset, nil
	}
	return M.Socksaddr{Fqdn: host, Port: port}, offset, nil
}

func (c *vmessUDPPacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	conn := c.conn
	last := c.source
	c.conn = nil
	c.pending = nil
	c.mu.Unlock()

	if conn != nil {
		// Best effort: tell the server the session is finished. The frame still
		// needs a well formed address, so the last seen destination is reused;
		// without one the END frame is skipped rather than sent malformed.
		if last.IsValid() {
			end := buildXUDPFrame(c.session, xudpStatusEnd, last, nil, nil)
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write(end)
		}
		return conn.Close()
	}
	return nil
}

func (c *vmessUDPPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (c *vmessUDPPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *vmessUDPPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *vmessUDPPacketConn) SetWriteDeadline(t time.Time) error { return nil }
