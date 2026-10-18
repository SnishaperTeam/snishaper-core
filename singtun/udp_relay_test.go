package singtun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/SnishaperTeam/snishaper-core/config"
)

// fakeRelayConn 是一个可在测试里喂数据的 N.PacketConn：
// 测试线程用 deliver 注入「来自客户端」的包，用 sent 取回「写回客户端」的包。
type fakeRelayConn struct {
	in     chan relayPacket
	sent   chan relayPacket
	closed chan struct{}
	once   sync.Once
}

type relayPacket struct {
	payload []byte
	dest    M.Socksaddr
}

func newFakeRelayConn() *fakeRelayConn {
	return &fakeRelayConn{
		in:     make(chan relayPacket, 8),
		sent:   make(chan relayPacket, 8),
		closed: make(chan struct{}),
	}
}

func (c *fakeRelayConn) deliver(payload []byte, dest M.Socksaddr) {
	select {
	case c.in <- relayPacket{payload: payload, dest: dest}:
	case <-c.closed:
	}
}

func (c *fakeRelayConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	select {
	case pkt := <-c.in:
		_, _ = b.Write(pkt.payload)
		return pkt.dest, nil
	case <-c.closed:
		return M.Socksaddr{}, net.ErrClosed
	case <-time.After(20 * time.Millisecond):
		return M.Socksaddr{}, timeoutError{}
	}
}

func (c *fakeRelayConn) WritePacket(b *buf.Buffer, dest M.Socksaddr) error {
	defer b.Release()
	select {
	case c.sent <- relayPacket{payload: append([]byte(nil), b.Bytes()...), dest: dest}:
	case <-c.closed:
	}
	return nil
}

func (c *fakeRelayConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeRelayConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *fakeRelayConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeRelayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeRelayConn) SetWriteDeadline(time.Time) error { return nil }

var _ N.PacketConn = (*fakeRelayConn)(nil)

// fakeRelayPeer 是隧道侧的假实现，记录被转发的包并可注入响应。
type fakeRelayPeer struct {
	mu       sync.Mutex
	received []relayPacket
	replies  chan relayPacket
	closed   chan struct{}
	once     sync.Once
}

func newFakeRelayPeer() *fakeRelayPeer {
	return &fakeRelayPeer{replies: make(chan relayPacket, 8), closed: make(chan struct{})}
}

func (p *fakeRelayPeer) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	select {
	case pkt := <-p.replies:
		_, _ = b.Write(pkt.payload)
		return pkt.dest, nil
	case <-p.closed:
		return M.Socksaddr{}, net.ErrClosed
	case <-time.After(20 * time.Millisecond):
		return M.Socksaddr{}, timeoutError{}
	}
}

func (p *fakeRelayPeer) WritePacket(b *buf.Buffer, dest M.Socksaddr) error {
	defer b.Release()
	p.mu.Lock()
	p.received = append(p.received, relayPacket{payload: append([]byte(nil), b.Bytes()...), dest: dest})
	p.mu.Unlock()
	return nil
}

func (p *fakeRelayPeer) SetReadDeadline(time.Time) error { return nil }

// FrontHeadroom makes the fake behave like the real SOCKS5 tunnel conn: the
// subscription dialer's packet conn reserves room so WritePacket can prepend the
// SOCKS5 header in place. sing's NewReadWaitOptions reads this interface, so a
// fake without it would wrongly show zero headroom.
func (p *fakeRelayPeer) FrontHeadroom() int { return relayTestHeadroom }

// relayTestHeadroom stands in for the SOCKS5 UDP header size (RSV+FRAG+ATYP+
// address+port), which is what the real tunnel conn reserves.
const relayTestHeadroom = 64

func (p *fakeRelayPeer) close() { p.once.Do(func() { close(p.closed) }) }

func (p *fakeRelayPeer) written() []relayPacket {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]relayPacket(nil), p.received...)
}

var _ packetRelayPeer = (*fakeRelayPeer)(nil)

// TestRelayUDPPacketForwardsBothDirections covers the new subscription-relay
// data path: a datagram from the TUN client must reach the proxy tunnel with its
// destination intact, and a tunnel response must be written back to the client.
func TestRelayUDPPacketForwardsBothDirections(t *testing.T) {
	h := NewHandler("127.0.0.1:1", nil, func(string) {})
	h.udpIdleSessionTTL.Store(int64(150 * time.Millisecond))

	conn := newFakeRelayConn()
	peer := newFakeRelayPeer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.relayUDPPacket(ctx, conn, peer, N.NewReadWaitOptions(conn, peer))
	}()
	defer func() {
		cancel()
		_ = conn.Close()
		peer.close()
	}()

	// 客户端 → 隧道
	target := M.SocksaddrFrom(netip.MustParseAddr("1.1.1.1"), 443)
	conn.deliver([]byte("outbound-datagram"), target)

	deadline := time.After(5 * time.Second)
	for {
		if got := peer.written(); len(got) > 0 {
			if string(got[0].payload) != "outbound-datagram" {
				t.Fatalf("tunnel payload = %q, want outbound-datagram", got[0].payload)
			}
			if got[0].dest.String() != target.String() {
				t.Fatalf("tunnel destination = %s, want %s", got[0].dest, target)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("client datagram never reached the proxy tunnel")
		case <-time.After(5 * time.Millisecond):
		}
	}

	// 隧道 → 客户端
	source := M.SocksaddrFrom(netip.MustParseAddr("8.8.8.8"), 53)
	peer.replies <- relayPacket{payload: []byte("inbound-datagram"), dest: source}

	for {
		select {
		case got := <-conn.sent:
			if string(got.payload) != "inbound-datagram" {
				t.Fatalf("client payload = %q, want inbound-datagram", got.payload)
			}
			if got.dest.String() != source.String() {
				t.Fatalf("client source = %s, want %s", got.dest, source)
			}
			return
		case <-deadline:
			t.Fatal("tunnel response never reached the client")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestRelayUDPPacketReleasesIdleSession mirrors the UDP socket-leak regression
// test for the relay path: both directions silent must still exit after the
// idle TTL, otherwise每 cancel a subscription UDP session the sockets leak.
func TestRelayUDPPacketReleasesIdleSession(t *testing.T) {
	h := NewHandler("127.0.0.1:1", nil, func(string) {})
	h.udpIdleSessionTTL.Store(int64(150 * time.Millisecond))

	conn := newFakeRelayConn()
	peer := newFakeRelayPeer()
	defer func() {
		_ = conn.Close()
		peer.close()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A background context reproduces production, where the ctx is never
		// cancelled, so the idle watchdog is the only exit.
		h.relayUDPPacket(context.Background(), conn, peer, N.NewReadWaitOptions(conn, peer))
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("relayUDPPacket did not exit after the idle TTL: both directions leaked")
	}
}

// TestRelayUDPPacketExitsOnContextCancel keeps the existing cancellation
// semantics intact after adding the idle watchdog.
func TestRelayUDPPacketExitsOnContextCancel(t *testing.T) {
	h := NewHandler("127.0.0.1:1", nil, func(string) {})
	conn := newFakeRelayConn()
	peer := newFakeRelayPeer()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.relayUDPPacket(ctx, conn, peer, N.NewReadWaitOptions(conn, peer))
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()
	defer func() {
		_ = conn.Close()
		peer.close()
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("relayUDPPacket did not exit on context cancellation")
	}
}

// TestRelayBuffersCarryHeaderHeadroom pins the bug that made the relay panic:
// WritePacket extends the header in place, so a relay buffer must reserve front
// headroom. A buffer from the plain pool has start==0 and would panic in
// SocksaddrSerializer.
func TestRelayBuffersCarryHeaderHeadroom(t *testing.T) {
	conn := newFakeRelayConn()
	peer := newFakeRelayPeer()
	options := N.NewReadWaitOptions(conn, peer)

	if !options.NeedHeadroom() {
		t.Fatal("relay read options report no headroom: WritePacket would panic on an in-place header write")
	}
	if options.FrontHeadroom < relayTestHeadroom {
		t.Fatalf("front headroom = %d, want >= %d (the SOCKS5 header size)", options.FrontHeadroom, relayTestHeadroom)
	}

	relayBuf := options.NewBufferSize(buf.UDPBufferSize)
	defer relayBuf.Release()
	if relayBuf.Start() < relayTestHeadroom {
		t.Fatalf("relay buffer start = %d, want >= front headroom %d", relayBuf.Start(), relayTestHeadroom)
	}

	// The plain pool must NOT be used here: this documents why the relay needs
	// NewReadWaitOptions. A plain packet buffer has no headroom, so the in-place
	// SOCKS5 header write would panic.
	plain := buf.NewPacket()
	defer plain.Release()
	if plain.Start() >= relayBuf.Start() {
		t.Fatalf("plain buffer start (%d) should be below the relay buffer start (%d)", plain.Start(), relayBuf.Start())
	}
}

// TestHandlerSetUDPRelayTogglesRelay checks the install/clear contract used by
// the manager, including the no-restart rewire path.
func TestHandlerSetUDPRelayTogglesRelay(t *testing.T) {
	h := NewHandler("127.0.0.1:1", nil, func(string) {})
	if h.getUDPRelay() != nil {
		t.Fatal("a fresh handler must not have a UDP relay installed")
	}

	relay := &stubUDPRelay{}
	h.SetUDPRelay(relay)
	if h.getUDPRelay() != relay {
		t.Fatal("SetUDPRelay did not install the relay")
	}

	h.SetUDPRelay(nil)
	if h.getUDPRelay() != nil {
		t.Fatal("SetUDPRelay(nil) did not clear the relay")
	}
}

type stubUDPRelay struct{}

func (stubUDPRelay) OpenUDP(context.Context, M.Socksaddr) (N.PacketConn, bool, error) {
	return nil, false, nil
}

var _ UDPRelay = stubUDPRelay{}

// TestNewPacketConnectionExUsesRelayWhenAvailable proves the relay is actually
// wired into the TUN handler: when OpenUDP succeeds, the datagram path must go
// through forwardUDPRelay (which owns and closes the client conn), not the
// direct path. This is what makes fake-ip UDP work over a subscription node.
func TestNewPacketConnectionExUsesRelayWhenAvailable(t *testing.T) {
	h := NewHandler("127.0.0.1:1", nil, func(string) {})
	h.udpIdleSessionTTL.Store(int64(50 * time.Millisecond))

	remote := newFakeRelayConn()
	relay := &recordingRelay{ok: true, conn: remote}
	h.SetUDPRelay(relay)

	client := newFakeRelayConn()

	closed := make(chan struct{}, 1)
	h.NewPacketConnectionEx(context.Background(), client, M.Socksaddr{},
		M.SocksaddrFrom(netip.MustParseAddr("1.1.1.1"), 443),
		func(error) {
			select {
			case closed <- struct{}{}:
			default:
			}
		})

	if !relay.called {
		t.Fatal("NewPacketConnectionEx did not consult the installed UDP relay")
	}

	// forwardUDPRelay closes the client conn when the session ends, which only
	// happens on the relay path.
	select {
	case <-client.closed:
	case <-time.After(10 * time.Second):
		t.Fatal("client conn was never closed: the relay path did not run")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("onClose was never called on the relay path")
	}
}

// TestNewPacketConnectionExRelayErrorIsReported pins the failure contract: when
// the relay claims the destination but cannot open the tunnel, the client conn
// must be closed and the error surfaced instead of silently falling through.
func TestNewPacketConnectionExRelayErrorIsReported(t *testing.T) {
	h := NewHandler("127.0.0.1:1", nil, func(string) {})

	wantErr := errors.New("node unreachable")
	relay := &recordingRelay{ok: true, err: wantErr}
	h.SetUDPRelay(relay)

	client := newFakeRelayConn()

	gotErr := make(chan error, 1)
	h.NewPacketConnectionEx(context.Background(), client, M.Socksaddr{},
		M.SocksaddrFrom(netip.MustParseAddr("1.1.1.1"), 443),
		func(err error) {
			select {
			case gotErr <- err:
			default:
			}
		})

	select {
	case <-client.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("client conn was not closed after a relay failure")
	}
	select {
	case err := <-gotErr:
		if !errors.Is(err, wantErr) {
			t.Fatalf("onClose error = %v, want %v", err, wantErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("onClose was never called after a relay failure")
	}
}

type recordingRelay struct {
	called bool
	ok     bool
	err    error
	conn   N.PacketConn
}

func (r *recordingRelay) OpenUDP(context.Context, M.Socksaddr) (N.PacketConn, bool, error) {
	r.called = true
	if r.err != nil {
		return nil, r.ok, r.err
	}
	if !r.ok {
		return nil, false, nil
	}
	return r.conn, true, nil
}

var _ UDPRelay = (*recordingRelay)(nil)

// TestManagerSetUDPRelayBeforeStart applies the relay to the live handler when
// the manager is already running, so toggling a subscription does not require a
// TUN restart.
func TestManagerSetUDPRelayBeforeStart(t *testing.T) {
	m := newManager(config.Brand{Name: "FlowWeaver"}, nil, func(string) {})
	if m.brand.Display() != "FlowWeaver" {
		t.Fatalf("manager brand = %q, want FlowWeaver", m.brand.Display())
	}

	relay := &stubUDPRelay{}
	m.SetUDPRelay(relay)

	m.mu.Lock()
	got := m.udpRelay
	handler := m.handler
	m.mu.Unlock()

	if got == nil {
		t.Fatal("SetUDPRelay did not store the relay on the manager")
	}
	if handler != nil && handler.getUDPRelay() == nil {
		t.Fatal("SetUDPRelay did not push the relay to the live handler")
	}
}

// TestManagerAdapterNameUsesBrand pins the user-visible adapter name: a branded
// embedder must not create a "SniShaper" network adapter, because users see that
// name in Windows settings and it breaks per-product cleanup.
func TestManagerAdapterNameUsesBrand(t *testing.T) {
	for _, tc := range []struct {
		name  string
		brand config.Brand
		want  string
	}{
		{"default", config.Brand{}, "SniShaper"},
		{"embedder", config.Brand{Name: "FlowWeaver"}, "FlowWeaver"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newManager(tc.brand, nil, func(string) {})
			if got := m.brand.Display(); got != tc.want {
				t.Fatalf("brand display = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBrandOwnNamesAreProductScoped guards the split between names used to
// delete/claim and shared driver names used only for recognition.
func TestBrandOwnNamesAreProductScoped(t *testing.T) {
	flowweaver := config.Brand{Name: "FlowWeaver"}
	names := flowweaver.OwnNames()
	joined := strings.Join(names, ",")

	if !strings.Contains(joined, "flowweaver") {
		t.Errorf("OwnNames() = %v, want the product name", names)
	}
	// The shared driver name must never be a claim/delete token.
	for _, shared := range []string{"singtun", "sing-tun"} {
		for _, name := range names {
			if name == shared {
				t.Errorf("OwnNames() must not contain the shared driver name %q", shared)
			}
		}
	}
	// Tunnels() is the recognition-only superset.
	tunnels := strings.Join(flowweaver.Tunnels(), ",")
	if !strings.Contains(tunnels, "sing-tun") {
		t.Errorf("Tunnels() = %v, want the shared driver names", flowweaver.Tunnels())
	}
}
