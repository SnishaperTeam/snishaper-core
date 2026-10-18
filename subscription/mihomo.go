package subscription

// mihomo.go routes nodes through the Clash core (mihomo) adapters. A node
// parsed from a subscription carries its raw Clash YAML mapping (Node.Raw);
// adapter.ParseProxy is the exact code path the mihomo core runs when it
// loads a config, so every protocol, transport and option — ws/grpc/h2
// transports, REALITY, mux/smux, uTLS client-fingerprint, ss2022, skip-cert-
// verify — behaves exactly like Clash. This replaces the hand-rolled dialers
// (which covered only a subset and mis-implemented the VMess AEAD key
// derivation), the same way Clash Verge delegates node tests to the core.
//
// The core's TCP conns satisfy net.Conn directly; UDP conns are bridged to
// the sagernet sing types FlowWeaver's TUN layer expects, because mihomo is
// built against the metacubex sing fork — the interface shapes are
// identical, the module paths are not.

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	mihomolog "github.com/metacubex/mihomo/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func init() {
	// The core adapters log dial failures via the mihomo logger, which
	// writes to stdout by default; silence it — errors come back as values.
	mihomolog.SetLevel(mihomolog.SILENT)
}

// MihomoProxy builds the Clash-core proxy for this node from its raw
// subscription config. It returns an error when the node carries no raw
// config (hand-constructed nodes; the legacy dialers apply there).
func (n Node) MihomoProxy() (C.Proxy, error) {
	if n.Raw == nil {
		return nil, fmt.Errorf("node %q has no raw clash config", n.Name)
	}
	proxy, err := adapter.ParseProxy(n.Raw)
	if err != nil {
		return nil, fmt.Errorf("node %q (%s): %w", n.Name, n.Type, err)
	}
	return proxy, nil
}

// URLTest runs the Clash-core delay test — the same adapter.Proxy.URLTest
// that backs mihomo's /proxies/:name/delay endpoint used by Clash Verge.
// It reports the delay in milliseconds; zero delay means failure, matching
// the core's REST semantics.
func (n Node) URLTest(ctx context.Context, testURL string) (uint16, error) {
	proxy, err := n.MihomoProxy()
	if err != nil {
		return 0, err
	}
	delay, err := proxy.URLTest(ctx, testURL, nil)
	if err != nil {
		return 0, err
	}
	if delay == 0 {
		return 0, fmt.Errorf("node %q: delay test failed", n.Name)
	}
	return delay, nil
}

// mihomoSupportsUDP asks the core adapter whether the parsed proxy carries
// UDP. A parse failure reports false so UDP falls back to the direct path.
func (n Node) mihomoSupportsUDP() bool {
	proxy, err := n.MihomoProxy()
	return err == nil && proxy.SupportUDP()
}

// dialMihomoTCP opens a TCP tunnel through the Clash-core adapter.
// The returned conn implements net.Conn (mihomo's C.Conn embeds it).
func (n Node) dialMihomoTCP(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	proxy, err := n.MihomoProxy()
	if err != nil {
		return nil, err
	}
	md := &C.Metadata{NetWork: C.TCP}
	if err := md.SetRemoteAddress(net.JoinHostPort(targetHost, strconv.Itoa(targetPort))); err != nil {
		return nil, fmt.Errorf("node %q: %w", n.Name, err)
	}
	conn, err := proxy.DialContext(ctx, md)
	if err != nil {
		return nil, fmt.Errorf("node %q: %w", n.Name, err)
	}
	return conn, nil
}

// listenPacketMihomoUDP opens a UDP relay through the Clash-core adapter and
// bridges it to the sing PacketConn FlowWeaver's TUN UDP relay expects.
func (n Node) listenPacketMihomoUDP(ctx context.Context, targetHost string, targetPort int) (N.PacketConn, error) {
	proxy, err := n.MihomoProxy()
	if err != nil {
		return nil, err
	}
	if !proxy.SupportUDP() {
		return nil, fmt.Errorf("node %q (%s): udp is not supported", n.Name, n.Type)
	}
	md := &C.Metadata{NetWork: C.UDP}
	if err := md.SetRemoteAddress(net.JoinHostPort(targetHost, strconv.Itoa(targetPort))); err != nil {
		return nil, fmt.Errorf("node %q: %w", n.Name, err)
	}
	pkt, err := proxy.ListenPacketContext(ctx, md)
	if err != nil {
		return nil, fmt.Errorf("node %q: %w", n.Name, err)
	}
	return &mihomoPacketConn{pc: pkt}, nil
}

// mihomoPacketConn adapts the core's net.PacketConn-shaped UDP relay to the
// sagernet sing N.PacketConn interface (FlowWeaver's TUN layer consumes the
// sagernet types; mihomo is built against the metacubex sing fork).
type mihomoPacketConn struct {
	pc C.PacketConn
}

func (c *mihomoPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	_, addr, err := buffer.ReadPacketFrom(c.pc)
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.SocksaddrFromNet(addr), nil
}

func (c *mihomoPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	// The core's WriteTo implementations parse the destination from
	// net.Addr.String(), which keeps domain destinations intact.
	_, err := c.pc.WriteTo(buffer.Bytes(), socksNetAddr{socks: destination})
	buffer.Release()
	return err
}

func (c *mihomoPacketConn) Close() error                      { return c.pc.Close() }
func (c *mihomoPacketConn) LocalAddr() net.Addr               { return c.pc.LocalAddr() }
func (c *mihomoPacketConn) SetDeadline(t time.Time) error     { return c.pc.SetDeadline(t) }
func (c *mihomoPacketConn) SetReadDeadline(t time.Time) error { return c.pc.SetReadDeadline(t) }

func (c *mihomoPacketConn) SetWriteDeadline(t time.Time) error {
	return c.pc.SetWriteDeadline(t)
}

// socksNetAddr renders a sing Socksaddr as the net.Addr the core's
// WriteTo implementations expect ("host:port", domains included).
type socksNetAddr struct {
	socks M.Socksaddr
}

func (a socksNetAddr) Network() string { return "udp" }
func (a socksNetAddr) String() string  { return a.socks.String() }

var _ N.PacketConn = (*mihomoPacketConn)(nil)
