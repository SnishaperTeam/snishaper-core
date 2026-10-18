package subscription

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// tuicUDPPacketConn relays datagrams as TUIC Packet commands over QUIC
// datagrams, which is the native (unordered, full cone) UDP mode.
//
// Packet command layout after the two byte header:
//
//	assoc_id(2) pkt_id(2) frag_total(1) frag_id(1) size(2) addr payload
//
// The address is present only on the first fragment; later fragments use the
// None marker. This client never fragments, so every packet is a single
// fragment with the address included.
type tuicUDPPacketConn struct {
	conn *tuicConn
	// assocID identifies this UDP session to the server.
	assocID uint16
	// readBuf holds a datagram already stripped of its command header.
	readBuf []byte
	// source is the address carried by the datagram in readBuf.
	source M.Socksaddr
}

func dialTUICUDP(ctx context.Context, node Node, host string, port int) (*tuicUDPPacketConn, error) {
	tc, err := dialTUIC(ctx, node)
	if err != nil {
		return nil, err
	}

	state := tc.quic.ConnectionState()
	if !state.SupportsDatagrams.Remote {
		tc.quic.CloseWithError(0, "server does not support datagrams")
		return nil, fmt.Errorf("tuic: server does not support the native udp mode")
	}

	tc.mu.Lock()
	assocID := tc.nextAssoc
	tc.nextAssoc++
	tc.mu.Unlock()

	target, err := encodeTUICAddr(host, port)
	if err != nil {
		tc.quic.CloseWithError(0, "bad address")
		return nil, err
	}

	pc := &tuicUDPPacketConn{conn: tc, assocID: assocID}
	// Open the session with an empty packet so the server registers the
	// assoc id before any real traffic flows.
	if err := pc.sendPacket(target, nil); err != nil {
		tc.quic.CloseWithError(0, "udp session setup failed")
		return nil, err
	}

	return pc, nil
}

func (c *tuicUDPPacketConn) sendPacket(addr []byte, payload []byte) error {
	frame := make([]byte, 0, 11+len(addr)+len(payload))
	frame = append(frame, tuicVersion, tuicCmdPacket)

	var ids [4]byte
	binary.BigEndian.PutUint16(ids[0:2], c.assocID)

	c.conn.mu.Lock()
	c.conn.nextPkt++
	pktID := c.conn.nextPkt
	c.conn.mu.Unlock()

	binary.BigEndian.PutUint16(ids[2:4], pktID)
	frame = append(frame, ids[:]...)

	frame = append(frame, 1) // frag_total: single fragment
	frame = append(frame, 0) // frag_id

	// SIZE counts the whole UDP datagram, so the address header is included.
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(addr)+len(payload)))
	frame = append(frame, size[:]...)
	frame = append(frame, addr...)
	frame = append(frame, payload...)

	return c.conn.quic.SendDatagram(frame)
}

func (c *tuicUDPPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	addr, err := encodeTUICAddr(destination.Fqdn, int(destination.Port))
	if err != nil {
		buffer.Release()
		return err
	}
	if destination.IsIP() {
		addr, err = encodeTUICAddr(destination.Addr.String(), int(destination.Port))
		if err != nil {
			buffer.Release()
			return err
		}
	}

	err = c.sendPacket(addr, buffer.Bytes())
	buffer.Release()
	return err
}

func (c *tuicUDPPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
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

// readOne blocks until the next datagram is decoded into readBuf.
func (c *tuicUDPPacketConn) readOne() error {
	for {
		if c.conn.isClosed() {
			return net.ErrClosed
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		frame, err := c.conn.quic.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			return err
		}

		payload, addr, ok := parseTUICPacket(frame)
		if !ok {
			// Not a Packet command (for example a server heartbeat).
			continue
		}
		c.readBuf = payload
		c.source = addr
		return nil
	}
}

// parseTUICPacket decodes a Packet command frame.
func parseTUICPacket(frame []byte) ([]byte, M.Socksaddr, bool) {
	if len(frame) < 2 {
		return nil, M.Socksaddr{}, false
	}
	if frame[0] != tuicVersion || frame[1] != tuicCmdPacket {
		return nil, M.Socksaddr{}, false
	}
	// assoc_id(2) pkt_id(2) frag_total(1) frag_id(1) size(2)
	if len(frame) < 11 {
		return nil, M.Socksaddr{}, false
	}
	fragTotal := frame[6]
	fragID := frame[7]
	// SIZE counts the whole UDP datagram, address header included.
	size := int(binary.BigEndian.Uint16(frame[8:10]))
	rest := frame[10:]

	// Only complete, single-fragment packets are handled; the client never
	// fragments, so anything else is skipped rather than mis-assembled.
	if fragTotal != 1 || fragID != 0 {
		return nil, M.Socksaddr{}, false
	}
	if size > len(rest) {
		return nil, M.Socksaddr{}, false
	}

	host, port, addrLen, err := readTUICAddr(rest)
	if err != nil {
		return nil, M.Socksaddr{}, false
	}
	if size < addrLen {
		return nil, M.Socksaddr{}, false
	}
	// The payload follows the address and runs to the end of the datagram.
	payload := rest[addrLen:size]

	return payload, tuicSocksaddr(host, port), true
}

func (c *tuicUDPPacketConn) Close() error {
	// Politely end the UDP session before tearing the QUIC connection down.
	_ = c.conn.quic.SendDatagram([]byte{tuicVersion, tuicCmdDissociate, 0, 0})
	c.conn.close()
	return nil
}

// LocalAddr reports a placeholder: a QUIC connection has no local UDP address
// callers can meaningfully use.
//
// The deadline setters are no-ops because quic.Conn has no deadline support;
// reads are bounded by the context timeout inside readOne instead.
func (c *tuicUDPPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (c *tuicUDPPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *tuicUDPPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *tuicUDPPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// tuicSocksaddr builds a sing address from a decoded TUIC address.
func tuicSocksaddr(host string, port int) M.Socksaddr {
	if ip := net.ParseIP(host); ip != nil {
		return M.Socksaddr{Addr: ipAddr(ip), Port: uint16(port)}
	}
	return M.Socksaddr{Fqdn: host, Port: uint16(port)}
}
