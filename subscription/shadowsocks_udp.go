package subscription

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// shadowsocksUDPPacketConn speaks the Shadowsocks UDP relay protocol.
//
// Every datagram is sealed on its own: a fresh random salt is generated per
// packet, an HKDF-SHA1 subkey is derived from the password key and that salt,
// and the whole datagram (SOCKS5 address followed by the payload) becomes a
// single AEAD message. This is deliberately different from the TCP transport,
// which uses one long-lived subkey split into separately keyed chunks, so the
// two paths must not share code beyond the key derivation.
type shadowsocksUDPPacketConn struct {
	inner net.PacketConn
	// server is the Shadowsocks endpoint datagrams are sent to.
	server *net.UDPAddr
	// spec describes the negotiated AEAD cipher.
	spec shadowsocksSpec
	// passwordKey is the EVP_BytesToKey output the salt feeds into.
	passwordKey []byte
}

func dialShadowsocksUDP(inner net.PacketConn, node Node) (N.PacketConn, error) {
	cipherName := node.Options["cipher"]
	if cipherName == "" {
		cipherName = node.Options["method"]
	}
	spec, ok := lookupShadowsocksSpec(cipherName)
	if !ok {
		return nil, fmt.Errorf("shadowsocks: unsupported cipher %q", cipherName)
	}
	password := node.Options["password"]
	if password == "" {
		return nil, fmt.Errorf("shadowsocks: password is required")
	}

	server, err := net.ResolveUDPAddr("udp", net.JoinHostPort(node.Server, fmt.Sprint(node.Port)))
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: resolving server failed: %w", err)
	}

	return &shadowsocksUDPPacketConn{
		inner:       inner,
		server:      server,
		spec:        spec,
		passwordKey: shadowsocksKey(password, spec.keySize),
	}, nil
}

// seal encrypts one datagram under a fresh salt.
func (c *shadowsocksUDPPacketConn) seal(payload []byte) ([]byte, error) {
	salt := make([]byte, c.spec.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	subkey, err := hkdfSHA1(c.passwordKey, salt, []byte("ss-subkey"), c.spec.keySize)
	if err != nil {
		return nil, err
	}

	aead, err := c.spec.factory(subkey)
	if err != nil {
		return nil, err
	}

	// The whole datagram is one AEAD message; there is no length prefix.
	sealed := aead.Seal(nil, make([]byte, aead.NonceSize()), payload, nil)
	return append(salt, sealed...), nil
}

// open decrypts one datagram given its salt.
func (c *shadowsocksUDPPacketConn) open(packet []byte) ([]byte, error) {
	if len(packet) < c.spec.saltSize {
		return nil, fmt.Errorf("shadowsocks: datagram shorter than the salt")
	}

	salt := packet[:c.spec.saltSize]
	subkey, err := hkdfSHA1(c.passwordKey, salt, []byte("ss-subkey"), c.spec.keySize)
	if err != nil {
		return nil, err
	}

	aead, err := c.spec.factory(subkey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, make([]byte, aead.NonceSize()), packet[c.spec.saltSize:], nil)
}

func (c *shadowsocksUDPPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	// Serialize the destination with sing's writer so domains keep their type
	// on the wire.
	addrWriter := buf.NewSize(M.SocksaddrSerializer.AddrPortLen(destination))
	defer addrWriter.Release()
	if err := M.SocksaddrSerializer.WriteAddrPort(addrWriter, destination); err != nil {
		buffer.Release()
		return err
	}
	addr := addrWriter.Bytes()

	// The datagram body is the SOCKS5 address followed by the payload.
	plain := make([]byte, 0, len(addr)+buffer.Len())
	plain = append(plain, addr...)
	plain = append(plain, buffer.Bytes()...)

	sealed, err := c.seal(plain)
	if err != nil {
		buffer.Release()
		return err
	}

	err = c.inner.SetWriteDeadline(time.Now().Add(defaultDialTimeout))
	if err == nil {
		_, err = c.inner.WriteTo(sealed, c.server)
	}
	buffer.Release()
	return err
}

func (c *shadowsocksUDPPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	raw := make([]byte, 65535)
	for {
		_ = c.inner.SetReadDeadline(time.Now().Add(defaultDialTimeout))
		n, _, err := c.inner.ReadFrom(raw)
		if err != nil {
			return M.Socksaddr{}, err
		}

		plain, err := c.open(raw[:n])
		if err != nil {
			// A datagram that cannot be decrypted is noise; skip it.
			continue
		}

		destination, addrLen, err := readSocksAddrBytes(plain)
		if err != nil {
			continue
		}
		buffer.Write(plain[addrLen:])
		return destination, nil
	}
}

// readSocksAddrBytes decodes the leading SOCKS5 address of a datagram and
// reports how many bytes it consumed.
func readSocksAddrBytes(b []byte) (M.Socksaddr, int, error) {
	if len(b) < 1 {
		return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
	}

	var host string
	var consumed int

	switch b[0] {
	case 0x01:
		if len(b) < 7 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(b[1:5]).String()
		consumed = 5
	case 0x03:
		nameLen := int(b[1])
		if len(b) < 2+nameLen+2 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		host = string(b[2 : 2+nameLen])
		consumed = 2 + nameLen
	case 0x04:
		if len(b) < 19 {
			return M.Socksaddr{}, 0, io.ErrUnexpectedEOF
		}
		host = net.IP(b[1:17]).String()
		consumed = 17
	default:
		return M.Socksaddr{}, 0, fmt.Errorf("shadowsocks: unsupported address type 0x%02x", b[0])
	}

	port := uint16(b[consumed])<<8 | uint16(b[consumed+1])
	consumed += 2

	if ip := net.ParseIP(host); ip != nil {
		return M.Socksaddr{Addr: ipAddr(ip), Port: port}, consumed, nil
	}
	return M.Socksaddr{Fqdn: host, Port: port}, consumed, nil
}

func (c *shadowsocksUDPPacketConn) Close() error                  { return c.inner.Close() }
func (c *shadowsocksUDPPacketConn) LocalAddr() net.Addr           { return c.inner.LocalAddr() }
func (c *shadowsocksUDPPacketConn) SetDeadline(t time.Time) error { return c.inner.SetDeadline(t) }
func (c *shadowsocksUDPPacketConn) SetReadDeadline(t time.Time) error {
	return c.inner.SetReadDeadline(t)
}
func (c *shadowsocksUDPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}
