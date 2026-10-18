package subscription

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// trojanUDPPacketConn tunnels UDP datagrams over a Trojan TCP connection.
//
// Wire format, per the sing-box compatibility notes:
//
//	opening packet: [56-byte hex key][CRLF][0x03][SOCKS5 addr][CRLF]
//	                [SOCKS5 addr][2-byte length][CRLF][payload]
//	later packets:  [SOCKS5 addr][2-byte length][CRLF][payload]
//
// The handshake destination and the first packet destination are both present;
// every packet after that carries only its own address.
type trojanUDPPacketConn struct {
	stream net.Conn
	// payload holds bytes already stripped of the framing, so a short read
	// does not lose the remainder.
	payload []byte
	// source is the address that sent the datagram currently in payload.
	source M.Socksaddr
	// opened tracks whether the opening handshake has been written.
	opened bool
}

func dialTrojanUDP(conn net.Conn, node Node, host string, port int) (N.PacketConn, error) {
	handshake, err := buildTrojanUDPHandshake(node, host, port, nil)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(handshake); err != nil {
		return nil, err
	}
	return &trojanUDPPacketConn{stream: conn, opened: true}, nil
}

// buildTrojanUDPHandshake renders the opening frame. When payload is non-nil it
// is appended as the first datagram; otherwise the frame carries a zero length
// and the caller sends the first packet through WritePacket.
func buildTrojanUDPHandshake(node Node, host string, port int, payload []byte) ([]byte, error) {
	sum := sha256.Sum224([]byte(node.Options["password"]))
	hexHash := make([]byte, 56)
	const hexDigits = "0123456789abcdef"
	for i, b := range sum {
		hexHash[i*2] = hexDigits[b>>4]
		hexHash[i*2+1] = hexDigits[b&0x0f]
	}

	addr, err := EncodeSocks5Addr(host, port)
	if err != nil {
		return nil, err
	}

	frame := make([]byte, 0, len(hexHash)+4+len(addr)*2+4+len(payload))
	frame = append(frame, hexHash...)
	frame = append(frame, 0x0d, 0x0a)
	frame = append(frame, trojanCommandUDP)
	frame = append(frame, addr...) // handshake destination
	frame = append(frame, 0x0d, 0x0a)
	frame = append(frame, addr...) // first packet destination

	// Length counts the trailing CRLF plus the payload.
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(payload)+2))
	frame = append(frame, length[:]...)
	frame = append(frame, 0x0d, 0x0a)
	frame = append(frame, payload...)

	return frame, nil
}

func (c *trojanUDPPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	// Serialize the destination with sing's writer so domains and IPs keep
	// their type on the wire.
	addrWriter := buf.NewSize(M.SocksaddrSerializer.AddrPortLen(destination))
	defer addrWriter.Release()
	if err := M.SocksaddrSerializer.WriteAddrPort(addrWriter, destination); err != nil {
		buffer.Release()
		return err
	}
	addr := addrWriter.Bytes()

	payload := buffer.Bytes()
	frame := make([]byte, 0, len(addr)+4+len(payload))
	frame = append(frame, addr...)

	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(payload)+2))
	frame = append(frame, length[:]...)
	frame = append(frame, 0x0d, 0x0a)
	frame = append(frame, payload...)

	_, writeErr := c.stream.Write(frame)
	buffer.Release()
	return writeErr
}

func (c *trojanUDPPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	for len(c.payload) == 0 {
		if err := c.readPacket(); err != nil {
			return M.Socksaddr{}, err
		}
	}

	buffer.Write(c.payload)
	source := c.source
	c.payload = nil
	return source, nil
}

// readPacket reads one framed datagram into c.payload.
func (c *trojanUDPPacketConn) readPacket() error {
	// The datagram destination uses the shared SOCKS5 serializer, which keeps
	// domain and IP addresses distinguishable.
	destination, err := M.SocksaddrSerializer.ReadAddrPort(c.stream)
	if err != nil {
		return err
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(c.stream, lengthBuf[:]); err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint16(lengthBuf[:]))
	if length < 2 || length > 65535 {
		return fmt.Errorf("trojan: invalid udp packet length %d", length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(c.stream, body); err != nil {
		return err
	}

	// The payload is preceded by a CRLF inside the framed body.
	c.payload = body[2:]
	c.source = destination
	return nil
}

func (c *trojanUDPPacketConn) Close() error                  { return c.stream.Close() }
func (c *trojanUDPPacketConn) LocalAddr() net.Addr           { return c.stream.LocalAddr() }
func (c *trojanUDPPacketConn) SetDeadline(t time.Time) error { return c.stream.SetDeadline(t) }
func (c *trojanUDPPacketConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}
func (c *trojanUDPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

var _ N.PacketConn = (*trojanUDPPacketConn)(nil)
