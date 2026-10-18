package subscription

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// TUIC v5 is a command based, multiplexed protocol carried over QUIC with
// TLS 1.3. Every command starts with a two byte header: version then type.
//
//	0x00 Authenticate  UUID(16) + token(32)      unidirectional stream
//	0x01 Connect       address                    bidirectional stream
//	0x02 Packet        assoc_id, pkt_id, frag…    QUIC datagram
//	0x03 Dissociate    assoc_id(2)
//	0x04 Heartbeat     (no payload)
//
// The token is derived with the TLS exporter, using the UUID as the label and
// the raw password as the context, so it is bound to the live TLS session.

const (
	tuicVersion byte = 0x05

	tuicCmdAuthenticate byte = 0x00
	tuicCmdConnect      byte = 0x01
	tuicCmdPacket       byte = 0x02
	tuicCmdDissociate   byte = 0x03
	tuicCmdHeartbeat    byte = 0x04

	// Address type markers defined by the TUIC specification.
	tuicAddrNone   byte = 0xFF
	tuicAddrDomain byte = 0x00
	tuicAddrIPv4   byte = 0x01
	tuicAddrIPv6   byte = 0x02
)

// tuicConn is one multiplexed TUIC session over a QUIC connection.
type tuicConn struct {
	quic   *quic.Conn
	uuid   [16]byte
	server string

	mu        sync.Mutex
	nextPkt   uint16
	nextAssoc uint16
	closed    bool
}

// dialTUIC establishes a QUIC connection and authenticates it.
func dialTUIC(ctx context.Context, node Node) (*tuicConn, error) {
	uuid, err := parseUUID(node.Options["uuid"])
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	password := node.Options["password"]
	if password == "" {
		return nil, fmt.Errorf("tuic: password is required")
	}

	serverName := node.Options["servername"]
	if serverName == "" {
		serverName = node.Server
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: node.Options["skip-cert-verify"] == "true", //nolint:gosec // mirrors the provider config
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3"},
	}

	quicConfig := &quic.Config{
		// Datagrams carry the native UDP relay mode.
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
	}

	serverAddr := net.JoinHostPort(node.Server, strconv.Itoa(node.Port))
	conn, err := quic.DialAddr(ctx, serverAddr, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("tuic: quic handshake failed: %w", err)
	}

	tc := &tuicConn{quic: conn, uuid: uuid, server: serverAddr}

	if err := tc.authenticate(password); err != nil {
		conn.CloseWithError(0, "authenticate failed")
		return nil, err
	}
	return tc, nil
}

// authenticate sends the Authenticate command on a unidirectional stream. TUIC
// allows other commands to be issued in parallel, so a failure here is reported
// but the session is torn down by the caller.
func (c *tuicConn) authenticate(password string) error {
	// The token is exported from the live TLS session (RFC 5705): the label is
	// the client UUID and the context is the raw password, so the token is
	// bound to this TLS session and cannot be replayed elsewhere.
	state := c.quic.ConnectionState().TLS
	token, err := state.ExportKeyingMaterial(string(c.uuid[:]), []byte(password), 32)
	if err != nil {
		return fmt.Errorf("tuic: exporting token failed: %w", err)
	}

	stream, err := c.quic.OpenUniStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("tuic: opening auth stream failed: %w", err)
	}

	payload := make([]byte, 0, 2+16+32)
	payload = append(payload, tuicVersion, tuicCmdAuthenticate)
	payload = append(payload, c.uuid[:]...)
	payload = append(payload, token...)

	if _, err := stream.Write(payload); err != nil {
		return fmt.Errorf("tuic: writing auth failed: %w", err)
	}
	// Closing the stream signals the end of the command; the server does not
	// reply on it.
	return stream.Close()
}

// dialTCP opens a bidirectional stream carrying a Connect command, then returns
// it as a net.Conn for the caller to read and write.
func (c *tuicConn) dialTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	addr, err := encodeTUICAddr(host, port)
	if err != nil {
		return nil, err
	}

	stream, err := c.quic.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("tuic: opening stream failed: %w", err)
	}

	header := make([]byte, 0, 2+len(addr))
	header = append(header, tuicVersion, tuicCmdConnect)
	header = append(header, addr...)

	if _, err := stream.Write(header); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("tuic: writing connect failed: %w", err)
	}

	return &tuicStreamConn{Stream: stream, server: c.server, cancel: stream.Close}, nil
}

// encodeTUICAddr renders a TUIC address: type byte, address, 2-byte port.
func encodeTUICAddr(host string, port int) ([]byte, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("tuic: invalid port %d", port)
	}

	var out []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, tuicAddrIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, tuicAddrIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("tuic: host too long: %d", len(host))
		}
		out = append(out, tuicAddrDomain, byte(len(host)))
		out = append(out, host...)
	}

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	return append(out, portBuf[:]...), nil
}

// readTUICAddr parses a TUIC address and returns host, port and bytes consumed.
func readTUICAddr(b []byte) (string, int, int, error) {
	if len(b) < 1 {
		return "", 0, 0, io.ErrUnexpectedEOF
	}

	var host string
	var offset int

	switch b[0] {
	case tuicAddrNone:
		offset = 1
	case tuicAddrDomain:
		if len(b) < 2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		nameLen := int(b[1])
		if len(b) < 2+nameLen+2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		host = string(b[2 : 2+nameLen])
		offset = 2 + nameLen
	case tuicAddrIPv4:
		if len(b) < 1+4+2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(b[1:5]).String()
		offset = 1 + 4
	case tuicAddrIPv6:
		if len(b) < 1+16+2 {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(b[1:17]).String()
		offset = 1 + 16
	default:
		return "", 0, 0, fmt.Errorf("tuic: unknown address type 0x%02x", b[0])
	}

	port := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	return host, port, offset + 2, nil
}

// tuicStreamConn adapts a QUIC bidirectional stream to net.Conn. QUIC streams
// are not bound to a socket address, so the addr methods return a placeholder
// that only carries the stream's network family.
type tuicStreamConn struct {
	*quic.Stream
	server string
	cancel func() error
	once   sync.Once
}

func (c *tuicStreamConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *tuicStreamConn) RemoteAddr() net.Addr {
	host, portStr, err := net.SplitHostPort(c.server)
	if err != nil {
		return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	}
	port, _ := strconv.Atoi(portStr)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
}

func (c *tuicStreamConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Stream.Close()
		_ = c.cancel()
	})
	return err
}

var _ net.Conn = (*tuicStreamConn)(nil)

// close tears down the QUIC connection once.
func (c *tuicConn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	_ = c.quic.CloseWithError(0, "closed")
}

func (c *tuicConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// ipAddr normalises a net.IP into a netip.Addr.
func ipAddr(ip net.IP) netip.Addr {
	if v4 := ip.To4(); v4 != nil {
		return netip.AddrFrom4([4]byte(v4))
	}
	if v6 := ip.To16(); v6 != nil {
		return netip.AddrFrom16([16]byte(v6))
	}
	return netip.Addr{}
}

// tuicSessionConn keeps the shared QUIC session alive for as long as any
// stream derived from it is open, and tears it down with the last stream.
type tuicSessionConn struct {
	net.Conn
	session *tuicConn
	once    sync.Once
}

func (c *tuicSessionConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.session.close() })
	return err
}
