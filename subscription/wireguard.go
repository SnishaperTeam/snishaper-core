package subscription

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mipstack"
	wgdevice "github.com/metacubex/wireguard-go/device"
	wgtun "github.com/metacubex/wireguard-go/tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	wgbind "github.com/metacubex/sing-wireguard"
)

// wireguardDefaultMTU matches what mihomo uses when the node does not say.
const wireguardDefaultMTU = 1408

// wireguardDialer is one configured WireGuard tunnel. Traffic is encrypted and
// sent by the device, while mipstack provides the user space IP stack, so no
// kernel interface or routing table entry is involved.
type wireguardDialer struct {
	stack    *mipstack.Stack
	device   *wgdevice.Device
	bind     *wgbind.ClientBind
	endpoint netip.AddrPort

	mu     sync.Mutex
	closed bool
}

// wireguardPool keeps one tunnel per node so the handshake cost is paid once.
// A WireGuard session is stateful, so it must be reused rather than rebuilt for
// every connection.
var (
	wireguardPoolMu sync.Mutex
	wireguardPool   = map[string]*wireguardDialer{}
)

// acquireWireguardDialer returns the shared tunnel for a node, creating it on
// first use.
func acquireWireguardDialer(node Node) (*wireguardDialer, error) {
	key := wireguardPoolKey(node)

	wireguardPoolMu.Lock()
	if d, ok := wireguardPool[key]; ok {
		wireguardPoolMu.Unlock()
		if d.isClosed() {
			// A previous close invalidated it; drop the entry and rebuild.
			wireguardPoolMu.Lock()
			delete(wireguardPool, key)
			wireguardPoolMu.Unlock()
		} else {
			return d, nil
		}
	} else {
		wireguardPoolMu.Unlock()
	}

	d, err := newWireguardDialer(node)
	if err != nil {
		return nil, err
	}

	wireguardPoolMu.Lock()
	// Another caller may have won the race; keep whichever landed first so a
	// single tunnel stays authoritative.
	if existing, ok := wireguardPool[key]; ok && !existing.isClosed() {
		wireguardPoolMu.Unlock()
		_ = d.Close()
		return existing, nil
	}
	wireguardPool[key] = d
	wireguardPoolMu.Unlock()

	return d, nil
}

// releaseWireguardDialer closes every pooled tunnel. It is used when the
// subscription is reloaded or the proxy shuts down.
func releaseWireguardDialer() {
	wireguardPoolMu.Lock()
	pool := wireguardPool
	wireguardPool = map[string]*wireguardDialer{}
	wireguardPoolMu.Unlock()

	for _, d := range pool {
		_ = d.Close()
	}
}

// ReleaseWireguardDialers closes every pooled WireGuard tunnel. Call it when
// the active subscription changes or the proxy shuts down; the next dial
// through a WireGuard node rebuilds its tunnel from scratch.
func ReleaseWireguardDialers() {
	releaseWireguardDialer()
}

// wireguardPoolKey identifies a tunnel by everything that shapes it.
func wireguardPoolKey(node Node) string {
	return strings.Join([]string{
		node.Name,
		node.Server,
		strconv.Itoa(node.Port),
		node.Options["private-key"],
		node.Options["public-key"],
		node.Options["pre-shared-key"],
		node.Options["ip"],
		node.Options["ipv6"],
		node.Options["reserved"],
		node.Options["allowed-ips"],
		node.Options["mtu"],
	}, "|")
}

func (d *wireguardDialer) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// wireguardConfig is the subset of a Clash wireguard node that matters here.
type wireguardConfig struct {
	server        string
	port          int
	privateKey    string
	publicKey     string
	preSharedKey  string
	localPrefixes []netip.Prefix
	reserved      [3]byte
	allowedIPs    []string
	mtu           int
}

// parseWireguardConfig reads the node options. Keys arrive base64 encoded from
// the subscription while the UAPI interface expects hex, so they are converted
// here rather than at each call site.
func parseWireguardConfig(node Node) (*wireguardConfig, error) {
	opts := node.Options

	cfg := &wireguardConfig{
		server:     node.Server,
		port:       node.Port,
		privateKey: opts["private-key"],
		publicKey:  opts["public-key"],
		mtu:        wireguardDefaultMTU,
	}

	if cfg.server == "" || cfg.port <= 0 {
		return nil, fmt.Errorf("wireguard: node %q is missing server or port", node.Name)
	}
	if cfg.privateKey == "" || cfg.publicKey == "" {
		return nil, fmt.Errorf("wireguard: node %q is missing a key", node.Name)
	}

	if mtu, err := strconv.Atoi(opts["mtu"]); err == nil && mtu > 0 {
		cfg.mtu = mtu
	}

	var err error
	if cfg.privateKey, err = wireguardKeyToHex(cfg.privateKey); err != nil {
		return nil, fmt.Errorf("wireguard: private key: %w", err)
	}
	if cfg.publicKey, err = wireguardKeyToHex(cfg.publicKey); err != nil {
		return nil, fmt.Errorf("wireguard: peer public key: %w", err)
	}
	if psk := opts["pre-shared-key"]; psk != "" {
		if cfg.preSharedKey, err = wireguardKeyToHex(psk); err != nil {
			return nil, fmt.Errorf("wireguard: pre-shared key: %w", err)
		}
	}

	// The ip/ipv6 fields are this end's address inside the tunnel.
	prefixes, err := wireguardLocalPrefixes(opts["ip"], opts["ipv6"])
	if err != nil {
		return nil, err
	}
	cfg.localPrefixes = prefixes

	reserved, err := parseWireguardReserved(opts["reserved"])
	if err != nil {
		return nil, err
	}
	cfg.reserved = reserved

	allowed := splitList(opts["allowed-ips"])
	if len(allowed) == 0 {
		// A single peer node without allowed-ips means "route everything",
		// which is what mihomo does.
		for _, p := range prefixes {
			if p.Addr().Is4() {
				allowed = append(allowed, "0.0.0.0/0")
			} else {
				allowed = append(allowed, "::/0")
			}
		}
	}
	cfg.allowedIPs = allowed

	return cfg, nil
}

// wireguardKeyToHex converts a base64 key into the hex form the UAPI expects.
// Providers ship base64, but hex is accepted too; hex is tried first because
// every hex digit is also a valid base64 character.
func wireguardKeyToHex(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", nil
	}

	if len(key)%2 == 0 {
		if _, err := hex.DecodeString(key); err == nil {
			return key, nil
		}
	}

	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// wireguardLocalPrefixes parses the tunnel-internal addresses.
func wireguardLocalPrefixes(ip, ipv6 string) ([]netip.Prefix, error) {
	var out []netip.Prefix

	appendPrefix := func(value string, bits int) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		if !strings.Contains(value, "/") {
			value = fmt.Sprintf("%s/%d", value, bits)
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return fmt.Errorf("wireguard: local address %q: %w", value, err)
		}
		out = append(out, prefix)
		return nil
	}

	if err := appendPrefix(ip, 32); err != nil {
		return nil, err
	}
	if err := appendPrefix(ipv6, 128); err != nil {
		return nil, err
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("wireguard: the node declares no tunnel address")
	}
	return out, nil
}

// parseWireguardReserved accepts either a three element list or the short
// string form Clash also allows. The list may still carry the brackets that a
// YAML flow sequence produces.
func parseWireguardReserved(value string) ([3]byte, error) {
	var out [3]byte
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	value = strings.TrimSpace(value)
	if value == "" {
		return out, nil
	}

	if parts := splitList(value); len(parts) == 3 {
		for i, part := range parts {
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || n > 255 {
				return out, fmt.Errorf("wireguard: reserved byte %q is not a number", part)
			}
			out[i] = byte(n)
		}
		return out, nil
	}

	// The compact form is a raw string, one byte per character.
	raw := []byte(value)
	if len(raw) > 3 {
		raw = raw[:3]
	}
	copy(out[:], raw)
	return out, nil
}

// splitList splits a comma or space separated option value.
func splitList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// newWireguardDialer builds the stack, the device and the bind, then applies
// the node configuration through the UAPI.
func newWireguardDialer(node Node) (*wireguardDialer, error) {
	cfg, err := parseWireguardConfig(node)
	if err != nil {
		return nil, err
	}

	stack, err := mipstack.New(mipstack.Config{
		LocalAddresses: cfg.localPrefixes,
		MTU:            uint32(cfg.mtu),
	})
	if err != nil {
		return nil, fmt.Errorf("wireguard: creating the ip stack failed: %w", err)
	}

	endpoint, err := resolveWireguardEndpoint(node.Server, cfg.port)
	if err != nil {
		_ = stack.Close()
		return nil, err
	}

	bind := wgbind.NewClientBind(
		context.Background(),
		wireguardErrorHandler{name: node.Name},
		nil,
		true,
		endpoint,
		cfg.reserved,
	)

	logger := &wgdevice.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(string, ...any) {},
	}

	dev := wgdevice.NewDevice(wireguardTunAdapter{stack: stack}, bind, logger, 0)

	d := &wireguardDialer{
		stack:    stack,
		device:   dev,
		bind:     bind,
		endpoint: endpoint,
	}

	if err := d.applyConfig(cfg); err != nil {
		_ = d.Close()
		return nil, err
	}

	// The stack must start before any socket is created through it.
	if err := stack.Start(); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("wireguard: starting the ip stack failed: %w", err)
	}

	return d, nil
}

// applyConfig sends the node configuration through the UAPI interface.
func (d *wireguardDialer) applyConfig(cfg *wireguardConfig) error {
	var b strings.Builder
	b.WriteString("private_key=" + cfg.privateKey + "\n")
	b.WriteString("listen_port=0\n")
	b.WriteString("public_key=" + cfg.publicKey + "\n")
	b.WriteString("endpoint=" + d.endpoint.String() + "\n")
	if cfg.preSharedKey != "" {
		b.WriteString("preshared_key=" + cfg.preSharedKey + "\n")
	}
	for _, allowed := range cfg.allowedIPs {
		b.WriteString("allowed_ip=" + allowed + "\n")
	}

	if err := d.device.IpcSet(b.String()); err != nil {
		return fmt.Errorf("wireguard: applying the configuration failed: %w", err)
	}
	return nil
}

// resolveWireguardEndpoint turns the server name into a UDP address, unmapping
// IPv4-in-IPv6 results which WireGuard rejects.
func resolveWireguardEndpoint(server string, port int) (netip.AddrPort, error) {
	if ip, err := netip.ParseAddr(server); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
	}

	ips, err := net.LookupIP(server)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("wireguard: resolving %q failed: %w", server, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			addr, ok := netip.AddrFromSlice(v4)
			if ok {
				return netip.AddrPortFrom(addr, uint16(port)), nil
			}
		}
	}
	if addr, ok := netip.AddrFromSlice(ips[0]); ok {
		return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
	}
	return netip.AddrPort{}, fmt.Errorf("wireguard: no usable address for %q", server)
}

// DialTCP opens a TCP connection to target through the tunnel.
func (d *wireguardDialer) DialTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("wireguard: destination %q must be an address: %w", host, err)
	}

	conn, err := d.stack.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(addr.Unmap(), uint16(port)))
	if err != nil {
		return nil, fmt.Errorf("wireguard: dialling %s:%d failed: %w", host, port, err)
	}
	return conn, nil
}

// ListenUDP returns a packet conn bound to the tunnel for datagram traffic.
func (d *wireguardDialer) ListenUDP(ctx context.Context) (net.PacketConn, error) {
	pc, err := d.stack.ListenUDP(ctx, "udp", netip.AddrPort{})
	if err != nil {
		return nil, fmt.Errorf("wireguard: opening a udap socket failed: %w", err)
	}
	return pc, nil
}

func (d *wireguardDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true

	if d.device != nil {
		d.device.Close()
	}
	if d.bind != nil {
		_ = d.bind.Close()
	}
	if d.stack != nil {
		return d.stack.Close()
	}
	return nil
}

// wireguardTunAdapter presents the user space stack as a TUN device. The file
// descriptor is nil because no kernel interface is involved.
type wireguardTunAdapter struct {
	stack *mipstack.Stack
}

func (a wireguardTunAdapter) File() *os.File { return nil }

func (a wireguardTunAdapter) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return a.stack.Read(bufs, sizes, offset)
}

func (a wireguardTunAdapter) Write(bufs [][]byte, offset int) (int, error) {
	return a.stack.Write(bufs, offset)
}

func (a wireguardTunAdapter) MTU() (int, error)     { return a.stack.MTU() }
func (a wireguardTunAdapter) Name() (string, error) { return a.stack.Name() }
func (a wireguardTunAdapter) BatchSize() int        { return a.stack.BatchSize() }
func (a wireguardTunAdapter) Close() error          { return a.stack.Close() }
func (a wireguardTunAdapter) Events() <-chan wgtun.Event {
	return nil
}

var _ wgtun.Device = wireguardTunAdapter{}

// wireguardErrorHandler surfaces bind level failures. The proxy reports them
// through its own log, so they are only printed when debugging is enabled.
type wireguardErrorHandler struct {
	name string
}

func (h wireguardErrorHandler) NewError(ctx context.Context, err error) {
	_ = fmt.Sprintf("%s: %v", h.name, err)
}

func (wireguardErrorHandler) Warning(ctx context.Context, msg string) {}
func (wireguardErrorHandler) Info(ctx context.Context, msg string)    {}
func (wireguardErrorHandler) Debug(ctx context.Context, msg string)   {}

var _ = time.Second

// DialTimeout opens a TCP tunnel to targetHost through the WireGuard node.
func (n Node) wgDialTCP(targetHost string, targetPort int) (net.Conn, error) {
	d, err := acquireWireguardDialer(n)
	if err != nil {
		return nil, err
	}

	// WireGuard routes by address, so a domain target has to be resolved by
	// the caller before the tunnel can be used.
	addr := targetHost
	if _, err := netip.ParseAddr(targetHost); err != nil {
		resolved, err := net.LookupIP(targetHost)
		if err != nil || len(resolved) == 0 {
			return nil, fmt.Errorf("wireguard: resolving %q failed: %w", targetHost, err)
		}
		for _, candidate := range resolved {
			if v4 := candidate.To4(); v4 != nil {
				parsed, ok := netip.AddrFromSlice(v4)
				if ok {
					addr = parsed.String()
					break
				}
			}
		}
		if _, err := netip.ParseAddr(addr); err != nil {
			return nil, fmt.Errorf("wireguard: no IPv4 address for %q", targetHost)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultDialTimeout)
	defer cancel()

	conn, err := d.DialTCP(ctx, addr, targetPort)
	if err != nil {
		// A dead tunnel must not poison the pool for later attempts.
		_ = d.Close()
		discardWireguardDialer(n)
		return nil, err
	}
	return conn, nil
}

// wgListenPacket opens a datagram socket inside the tunnel, adapted to sing's
// PacketConn so the TUN layer can hand buffers straight through.
func (n Node) wgListenPacket(ctx context.Context) (N.PacketConn, error) {
	d, err := acquireWireguardDialer(n)
	if err != nil {
		return nil, err
	}
	pc, err := d.ListenUDP(ctx)
	if err != nil {
		_ = d.Close()
		discardWireguardDialer(n)
		return nil, err
	}
	return &wireguardPacketConn{inner: pc}, nil
}

// wireguardPacketConn presents the tunnel's datagram socket as a sing
// PacketConn. The tunnel socket is a plain net.PacketConn, so the address
// carried in a buffer is unknown and reported as the unspecified address.
type wireguardPacketConn struct {
	inner net.PacketConn
}

func (c *wireguardPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	chunk := buffer.Extend(buffer.Len() + 65535)
	n, _, err := c.inner.ReadFrom(chunk)
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Resize(0, n)
	return M.Socksaddr{}, nil
}

func (c *wireguardPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	var addr net.Addr
	if destination.IsValid() {
		if ap := netip.AddrPortFrom(destination.Addr, destination.Port); ap.IsValid() {
			addr = net.UDPAddrFromAddrPort(ap)
		}
	}
	_, err := c.inner.WriteTo(buffer.Bytes(), addr)
	buffer.Release()
	return err
}

func (c *wireguardPacketConn) Close() error                       { return c.inner.Close() }
func (c *wireguardPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wireguardPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wireguardPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wireguardPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

var _ N.PacketConn = (*wireguardPacketConn)(nil)

// discardWireguardDialer drops a failed tunnel from the pool.
func discardWireguardDialer(node Node) {
	wireguardPoolMu.Lock()
	delete(wireguardPool, wireguardPoolKey(node))
	wireguardPoolMu.Unlock()
}
