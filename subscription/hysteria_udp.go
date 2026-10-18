package subscription

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// hysteriaUDPPacketConn relays datagrams as official Hysteria 2 UDPMessage
// frames (apernet/hysteria core/internal/protocol/proxy.go) carried on QUIC
// datagrams:
//
//	Session ID (uint32 BE)
//	Packet ID (uint16 BE)
//	Fragment ID (uint8)
//	Fragment count (uint8)
//	Address length (QUIC varint)
//	Address ("host:port")
//	Data...
//
// Only unfragmented datagrams (fragment count = 1) are exchanged; DNS-scale
// traffic always fits, and a larger payload is dropped with an error rather
// than silently truncated.
type hysteriaUDPPacketConn struct {
	session *hysteriaSession
	// readBuf holds a reassembled datagram waiting to be handed over.
	readBuf []byte
	// source is the address carried by the datagram in readBuf.
	source M.Socksaddr

	// nextSession hands out session ids for outgoing datagrams.
	nextSession uint32
	// nextPacket counts packets within the session, matching the official
	// client's per-session packet counter.
	nextPacket uint16
}

// maxUDPPayload is the practical datagram size: a QUIC datagram must fit into
// one packet, and the official client keeps messages within the same bound.
const maxUDPPayload = 1152

func dialHysteriaUDP(ctx context.Context, node Node, host string, port int) (*hysteriaUDPPacketConn, error) {
	session, err := dialHysteria(ctx, node)
	if err != nil {
		return nil, err
	}
	if !session.udpOK {
		session.close()
		return nil, fmt.Errorf("hysteria2: server does not support udp relay")
	}

	target, err := encodeHysteriaAddr(host, port)
	if err != nil {
		session.close()
		return nil, err
	}
	if len(target) > maxAddressLength {
		session.close()
		return nil, fmt.Errorf("hysteria2: udp target address too long")
	}

	pc := &hysteriaUDPPacketConn{session: session}
	// Register the session with an empty datagram so the server allocates the
	// association before real traffic starts.
	if err := pc.sendRaw(target, nil); err != nil {
		session.close()
		return nil, err
	}
	return pc, nil
}

func (c *hysteriaUDPPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	payload := buffer.Bytes()
	if len(payload) > maxUDPPayload {
		buffer.Release()
		return fmt.Errorf("hysteria2: udp payload %d exceeds the datagram limit", len(payload))
	}
	addr, err := encodeHysteriaAddr(tuicHostOf(destination), int(destination.Port))
	if err != nil {
		buffer.Release()
		return err
	}
	err = c.sendRaw(addr, payload)
	buffer.Release()
	return err
}

// sendRaw serializes one unfragmented UDPMessage and sends it as a raw QUIC
// datagram — no length or type prefix, the session id starts the message.
func (c *hysteriaUDPPacketConn) sendRaw(addr, payload []byte) error {
	c.session.mu.Lock()
	sessionID := c.nextSession
	packetID := c.nextPacket
	c.nextSession++
	c.nextPacket++
	c.session.mu.Unlock()
	return c.session.quic.SendDatagram(buildHysteriaUDPMessage(sessionID, packetID, addr, payload))
}

// buildHysteriaUDPMessage renders one official UDPMessage datagram:
//
//	Session ID (uint32 BE), Packet ID (uint16 BE),
//	Fragment ID (uint8), Fragment count (uint8),
//	Address length (QUIC varint), Address, Data.
func buildHysteriaUDPMessage(sessionID uint32, packetID uint16, addr, payload []byte) []byte {
	msg := make([]byte, 0, 8+len(addr)+len(payload))
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], sessionID)
	var pid [2]byte
	binary.BigEndian.PutUint16(pid[:], packetID)
	msg = append(msg, sid[:]...)
	msg = append(msg, pid[:]...)
	msg = append(msg, 0x00, 0x01) // fragment id 0 of 1
	msg = append(msg, addr...)
	msg = append(msg, payload...)
	return msg
}

func (c *hysteriaUDPPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	for len(c.readBuf) == 0 {
		if err := c.readOne(); err != nil {
			return M.Socksaddr{}, err
		}
	}
	buffer.Write(c.readBuf)
	source := c.source
	c.readBuf = nil
	return source, nil
}

// readOne receives datagrams until one parses into an unfragmented UDPMessage.
func (c *hysteriaUDPPacketConn) readOne() error {
	for {
		if c.session.isClosed() {
			return net.ErrClosed
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		frame, err := c.session.quic.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			return err
		}

		payload, addr, err := parseHysteriaUDPMessage(frame)
		if err != nil {
			// Malformed or fragmented datagrams are skipped, not fatal.
			continue
		}
		c.readBuf = payload
		c.source = hysteriaSocksaddr(addr)
		return nil
	}
}

// parseHysteriaUDPMessage decodes one UDPMessage datagram. It reports an error
// for malformed input and fragmented messages (which this client never
// assembles) are rejected the same way and skipped by the caller.
func parseHysteriaUDPMessage(frame []byte) (payload []byte, addr []byte, err error) {
	if len(frame) < 8 {
		return nil, nil, fmt.Errorf("hysteria2: datagram too short")
	}
	// session id (4) + packet id (2) + fragment id (1) + fragment count (1)
	if frame[7] != 1 {
		return nil, nil, fmt.Errorf("hysteria2: fragmented datagram")
	}
	rest := frame[8:]

	length, n, err := consumeQUICVarint(rest)
	if err != nil {
		return nil, nil, fmt.Errorf("hysteria2: bad address length: %w", err)
	}
	if length == 0 || uint64(len(rest)-n) < length {
		return nil, nil, fmt.Errorf("hysteria2: address overruns the datagram")
	}
	addr = rest[n : n+int(length)]
	payload = rest[n+int(length):]
	if len(payload) == 0 {
		return nil, nil, fmt.Errorf("hysteria2: datagram carries no data")
	}
	return payload, addr, nil
}

// hysteriaSocksaddr decodes a "host:port" address into a sing address. The
// input is the address field without its length prefix.
func hysteriaSocksaddr(addr []byte) M.Socksaddr {
	if len(addr) == 0 {
		return M.Socksaddr{}
	}

	host, portStr, err := net.SplitHostPort(string(addr))
	if err != nil {
		return M.Socksaddr{}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return M.Socksaddr{}
	}
	if ip := net.ParseIP(host); ip != nil {
		return M.Socksaddr{Addr: ipAddr(ip), Port: uint16(port)}
	}
	return M.Socksaddr{Fqdn: host, Port: uint16(port)}
}

// tuicHostOf returns the host part of a sing address.
func tuicHostOf(addr M.Socksaddr) string {
	if addr.IsDomain() {
		return addr.Fqdn
	}
	return addr.Addr.String()
}

// maxAddressLength mirrors the official protocol limit on encoded addresses.
const maxAddressLength = 2048

func (c *hysteriaUDPPacketConn) Close() error {
	c.session.close()
	return nil
}

// A QUIC connection has no local UDP address callers can use, and quic.Conn
// offers no deadline methods, so reads are bounded by the context timeout in
// readOne instead.
func (c *hysteriaUDPPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (c *hysteriaUDPPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *hysteriaUDPPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *hysteriaUDPPacketConn) SetWriteDeadline(t time.Time) error { return nil }
