package subscription

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Hysteria 2 authenticates with an HTTP/3 POST to /auth and expects status
// 233. TCP relays then run over unidirectional streams opened with a
// TCPRequest frame; UDP rides on QUIC datagrams as UDPRequest frames.
//
//	TCPRequest (0x401):  [varint length][address][varint padding len][padding]
//	UDPRequest (0x402):  [varint length][address][varint padding len][padding][data]
//	Response:            [uint8 status][varint message len][message][padding]
const (
	hysteriaTCPMsgType uint64 = 0x401
	hysteriaUDPMsgType uint64 = 0x402

	hysteriaStatusOK    byte = 0x00
	hysteriaStatusError byte = 0x01

	// hysteriaAuthOK is the non-standard status the server replies with.
	hysteriaAuthOK = 233
)

// hysteriaSession is an authenticated Hysteria 2 connection.
type hysteriaSession struct {
	quic *quic.Conn
	// transport owns the QUIC connection and must outlive it, otherwise the
	// connection is torn down as soon as the http3 client is collected.
	transport *http3.Transport
	socket    *net.UDPConn
	udpOK     bool
	mu        sync.Mutex
	closed    bool
}

// hysteriaDialer builds the authenticated session: it dials QUIC over the
// (optionally obfuscated) socket, runs the HTTP/3 handshake, and hands the
// live connection back for relaying.
type hysteriaDialer struct {
	node     Node
	password string
	conn     *quic.Conn
	udpConn  *net.UDPConn
	remote   *net.UDPAddr
}

// dial binds the UDP socket and prepares the dial function. The QUIC
// connection itself is established by the http3 transport.
func (d *hysteriaDialer) prepare() error {
	serverAddr := net.JoinHostPort(d.node.Server, strconv.Itoa(d.node.Port))
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fmt.Errorf("hysteria2: opening udp socket failed: %w", err)
	}
	d.udpConn = udpConn

	remote, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("hysteria2: resolving server failed: %w", err)
	}
	d.remote = remote
	return nil
}

func (d *hysteriaDialer) dial(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	var packetConn net.PacketConn = d.udpConn
	if obfsPassword := d.node.Options["obfs-password"]; obfsPassword != "" {
		if !strings.EqualFold(d.node.Options["obfs"], "salamander") {
			return nil, fmt.Errorf("hysteria2: unsupported obfs type %q", d.node.Options["obfs"])
		}
		packetConn = newSalamanderConn(d.udpConn, []byte(obfsPassword))
	}

	conn, err := quic.Dial(ctx, packetConn, d.remote, tlsCfg, cfg)
	if err != nil {
		return nil, err
	}
	d.conn = conn
	return conn, nil
}

// hysteriaTLSConfig builds the QUIC TLS configuration. When the subscription
// pins the server certificate (hysteria2 `fingerprint` field / share-link
// pinSHA256) the chain check is skipped and the leaf certificate is verified
// against that pin instead — the same semantics as the official client.
func hysteriaTLSConfig(node Node, serverName string) *tls.Config {
	cfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
	}
	if pin := strings.ToLower(strings.TrimSpace(node.Options["pinSHA256"])); pin != "" {
		cfg.InsecureSkipVerify = true //nolint:gosec // the pin replaces chain verification
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("hysteria2: server presented no certificate to pin")
			}
			sum := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(sum[:]) != pin {
				return fmt.Errorf("hysteria2: server certificate does not match the pinned fingerprint")
			}
			return nil
		}
		return cfg
	}
	cfg.InsecureSkipVerify = node.Options["skip-cert-verify"] == "true" //nolint:gosec // mirrors the provider config
	return cfg
}

// dialHysteria authenticates over HTTP/3 and returns a ready session.
func dialHysteria(ctx context.Context, node Node) (*hysteriaSession, error) {
	password := node.Options["password"]
	if password == "" {
		return nil, fmt.Errorf("hysteria2: password is required")
	}

	serverName := node.Options["servername"]
	if serverName == "" {
		serverName = node.Server
	}

	dialer := &hysteriaDialer{node: node, password: password}
	if err := dialer.prepare(); err != nil {
		return nil, err
	}

	transport := &http3.Transport{
		TLSClientConfig: hysteriaTLSConfig(node, serverName),
		QUICConfig:      &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 10 * time.Second},
		EnableDatagrams: true,
		Dial:            dialer.dial,
	}
	// The transport owns the QUIC connection it dials, so it must stay alive
	// for as long as the session does. It is handed to the session on success
	// and closed here only on the failure paths below.
	keepTransport := false
	defer func() {
		if !keepTransport {
			transport.Close()
		}
	}()

	// The official protocol sends the auth request with the literal host
	// "hysteria" (apernet/hysteria core/internal/protocol.URLHost): the server
	// treats any other host as masquerade traffic and proxies it to the decoy
	// site, which is why a request to https://<sni>/auth gets a plain 404.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	if err != nil {
		dialer.close()
		return nil, fmt.Errorf("hysteria2: building auth request failed: %w", err)
	}
	req.Header.Set("Hysteria-Auth", password)
	req.Header.Set("Hysteria-CC-RX", "0")
	req.Header.Set("Hysteria-Padding", randomPadding(256, 2048))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		dialer.close()
		return nil, fmt.Errorf("hysteria2: auth request failed: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	if resp.StatusCode != hysteriaAuthOK {
		dialer.close()
		return nil, fmt.Errorf("hysteria2: authentication rejected with status %d", resp.StatusCode)
	}
	if dialer.conn == nil {
		dialer.close()
		return nil, fmt.Errorf("hysteria2: server did not establish a quic connection")
	}

	udpOK := strings.EqualFold(resp.Header.Get("Hysteria-UDP"), "true")
	keepTransport = true
	return &hysteriaSession{
		quic:      dialer.conn,
		transport: transport,
		socket:    dialer.udpConn,
		udpOK:     udpOK,
	}, nil
}

func (d *hysteriaDialer) close() {
	if d.conn != nil {
		_ = d.conn.CloseWithError(0, "closed")
	}
	if d.udpConn != nil {
		_ = d.udpConn.Close()
	}
}

// hysteriaDialDeadline bounds the TCPRequest/TCPResponse exchange on a relay
// stream; quic streams have no inherent deadline and the dial ctx does not
// cover stream reads.
const hysteriaDialDeadline = 10 * time.Second

// dialTCP opens a bidirectional stream carrying a TCPRequest frame. A
// unidirectional stream cannot work here because the relay is full duplex.
func (s *hysteriaSession) dialTCP(ctx context.Context, host string, port int) (net.Conn, error) {
	stream, err := s.quic.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: opening stream failed: %w", err)
	}

	frame, err := buildHysteriaTCPRequest(host, port)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}

	// A server that accepts the frame but stalls would otherwise hang the
	// caller forever, hence the stream deadline for the handshake exchange.
	if err := stream.SetDeadline(time.Now().Add(hysteriaDialDeadline)); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("hysteria2: setting stream deadline failed: %w", err)
	}
	if _, err := stream.Write(frame); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("hysteria2: writing request failed: %w", err)
	}

	// The server answers with a response frame before any payload flows, so it
	// must be consumed here: relaying data on a rejected request would send the
	// client's bytes into a dead stream.
	ok, msg, err := readHysteriaTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	// The handshake is done; the caller owns the stream from here on.
	_ = stream.SetDeadline(time.Time{})
	if !ok {
		_ = stream.Close()
		return nil, fmt.Errorf("hysteria2: relay rejected: %s", msg)
	}

	return &hysteriaTCPConn{Stream: stream, session: s}, nil
}

// readHysteriaTCPResponse consumes the TCPResponse that follows a request,
// matching the official wire format:
//
//	Status (byte, 0=ok, 1=error)
//	Message length (QUIC varint)
//	Message (bytes)
//	Padding length (QUIC varint)
//	Padding (bytes)
//
// There is no outer length or type header — the response starts directly with
// the status byte.
func readHysteriaTCPResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", fmt.Errorf("hysteria2: reading response status failed: %w", err)
	}

	length, _, err := consumeQUICVarintFrom(r)
	if err != nil {
		return false, "", fmt.Errorf("hysteria2: reading response message length failed: %w", err)
	}
	if length > 2048 {
		return false, "", fmt.Errorf("hysteria2: response message length %d exceeds the protocol limit", length)
	}
	msg := make([]byte, length)
	if _, err := io.ReadFull(r, msg); err != nil {
		return false, "", fmt.Errorf("hysteria2: reading response message failed: %w", err)
	}

	paddingLen, _, err := consumeQUICVarintFrom(r)
	if err != nil {
		return false, "", fmt.Errorf("hysteria2: reading response padding length failed: %w", err)
	}
	if paddingLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(paddingLen)); err != nil {
			return false, "", fmt.Errorf("hysteria2: skipping response padding failed: %w", err)
		}
	}
	return status[0] == hysteriaStatusOK, string(msg), nil
}

// buildHysteriaTCPRequest renders the official TCPRequest frame
// (apernet/hysteria core/internal/protocol/proxy.go):
//
//	FrameTypeTCPRequest (0x401, QUIC varint)
//	Address length (QUIC varint)
//	Address ("host:port")
//	Padding length (QUIC varint)
//	Padding (64-511 random bytes)
//
// There is no outer length prefix: the frame type comes first, which is what
// the server's stream reader dispatches on.
func buildHysteriaTCPRequest(host string, port int) ([]byte, error) {
	addr, err := encodeHysteriaAddr(host, port)
	if err != nil {
		return nil, err
	}
	// The official client pads TCP requests with 64-511 random bytes.
	padding := make([]byte, 64+mathrand.Intn(448))
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}

	frame := make([]byte, 0, 16+len(addr)+len(padding))
	frame = appendQUICVarint(frame, hysteriaTCPMsgType)
	frame = append(frame, addr...)
	frame = appendQUICVarint(frame, uint64(len(padding)))
	return append(frame, padding...), nil
}

// encodeHysteriaAddr renders the target as a "host:port" string prefixed with
// its length as a QUIC varint.
//
// The specification carries the address as text rather than a packed SOCKS5
// style struct, which is what makes it unambiguous on the wire: there is no
// type byte to guess at when decoding.
func encodeHysteriaAddr(host string, port int) ([]byte, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("hysteria2: invalid port %d", port)
	}
	if strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("hysteria2: empty host")
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))
	out := appendQUICVarint(nil, uint64(len(address)))
	return append(out, address...), nil
}

// readHysteriaAddr decodes a length prefixed "host:port" address and returns
// it along with the offset just past it.
func readHysteriaAddr(b []byte) (host string, port int, consumed int, err error) {
	length, n, err := consumeQUICVarint(b)
	if err != nil {
		return "", 0, 0, err
	}
	rest := b[n:]
	if uint64(len(rest)) < length {
		return "", 0, 0, fmt.Errorf("hysteria2: address length %d exceeds the buffer", length)
	}

	address := string(rest[:length])
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, 0, fmt.Errorf("hysteria2: malformed address %q: %w", address, err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", 0, 0, fmt.Errorf("hysteria2: malformed port in %q", address)
	}

	return host, port, n + int(length), nil
}

// appendQUICVarint appends a QUIC variable length integer (RFC 9000 §16).
func appendQUICVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v <= 1073741823:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	case v <= 4611686018427387903:
		out := make([]byte, 8)
		binary.BigEndian.PutUint64(out, v)
		out[0] |= 0xC0
		return append(b, out...)
	default:
		return b
	}
}

// consumeQUICVarint reads one varint from b and returns its value and the
// number of bytes consumed.
func consumeQUICVarint(b []byte) (uint64, int, error) {
	if len(b) < 1 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	if len(b) < length {
		return 0, 0, io.ErrUnexpectedEOF
	}
	value := uint64(b[0] & 0x3F)
	for i := 1; i < length; i++ {
		value = value<<8 | uint64(b[i])
	}
	return value, length, nil
}

func (s *hysteriaSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	// Closing the transport tears down the QUIC connection it owns.
	if s.transport != nil {
		s.transport.Close()
	} else {
		_ = s.quic.CloseWithError(0, "closed")
	}
	if s.socket != nil {
		_ = s.socket.Close()
	}
}

func (s *hysteriaSession) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// hysteriaTCPConn adapts a Hysteria 2 bidirectional stream to net.Conn and
// keeps the shared QUIC session alive until the stream is closed.
type hysteriaTCPConn struct {
	*quic.Stream
	session *hysteriaSession
	once    sync.Once
}

func (c *hysteriaTCPConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Stream.Close()
		c.session.close()
	})
	return err
}

// QUIC streams are not bound to a socket address, so the addr methods report a
// placeholder that only carries the network family.
func (c *hysteriaTCPConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *hysteriaTCPConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }

var _ net.Conn = (*hysteriaTCPConn)(nil)

// randRead fills b with cryptographically secure random bytes.
func randRead(b []byte) (int, error) {
	return rand.Read(b)
}

// randomPadding returns a random alphanumeric string with a length in
// [min, max), matching the official client's Hysteria-Padding header.
func randomPadding(min, max int) string {
	n := min + mathrand.Intn(max-min)
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = chars[mathrand.Intn(len(chars))]
	}
	return string(buf)
}

// randomHex returns a hex string of n random bytes.
func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

// consumeQUICVarintFrom reads a single QUIC varint from a stream.
func consumeQUICVarintFrom(r io.Reader) (value uint64, size int, err error) {
	var first [1]byte
	if _, err = io.ReadFull(r, first[:]); err != nil {
		return 0, 0, err
	}
	length := 1 << (first[0] >> 6)
	buf := make([]byte, length)
	buf[0] = first[0]
	if length > 1 {
		if _, err = io.ReadFull(r, buf[1:]); err != nil {
			return 0, 0, err
		}
	}
	return consumeQUICVarint(buf)
}
