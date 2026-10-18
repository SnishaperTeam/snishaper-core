package subscription

import (
	"crypto/rand"
	"net"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Salamander is the packet obfuscation Hysteria 2 can put underneath QUIC.
// Each UDP datagram is prefixed with an 8 byte salt, and the remainder is XORed
// with a key derived from the pre-shared password and that salt:
//
//	send: [salt][payload XOR blake2b256(PSK + salt)]
//
// It wraps the net.PacketConn handed to quic-go, so the QUIC layer sees an
// ordinary datagram socket and needs no knowledge of the transform.
const salamanderSaltLen = 8

// salamanderConn applies the transform in both directions.
type salamanderConn struct {
	inner net.PacketConn
	psk   []byte
}

// newSalamanderConn wraps conn. An empty psk disables obfuscation, which is the
// default for Hysteria 2 nodes that do not configure obfs.
func newSalamanderConn(inner net.PacketConn, psk []byte) net.PacketConn {
	if len(psk) == 0 {
		return inner
	}
	return &salamanderConn{inner: inner, psk: append([]byte(nil), psk...)}
}

// WriteTo obfuscates a datagram before sending it.
func (c *salamanderConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	out := make([]byte, salamanderSaltLen+len(p))
	salt := out[:salamanderSaltLen]
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}

	key := salamanderKey(c.psk, salt)
	for i := range p {
		out[salamanderSaltLen+i] = p[i] ^ key[i%32]
	}

	if _, err := c.inner.WriteTo(out, addr); err != nil {
		return 0, err
	}
	// Report the plaintext length, which is what the caller handed over.
	return len(p), nil
}

// ReadFrom deobfuscates inbound datagrams.
func (c *salamanderConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.inner.ReadFrom(p)
		if err != nil {
			return 0, addr, err
		}
		if n < salamanderSaltLen {
			// Too short to carry a salt; treat it as noise and keep reading.
			continue
		}

		raw := p[:n]
		salt := raw[:salamanderSaltLen]
		key := salamanderKey(c.psk, salt)
		// The key index is the byte's position within the payload, so the
		// salt offset must not be included here.
		for i := salamanderSaltLen; i < len(raw); i++ {
			raw[i] ^= key[(i-salamanderSaltLen)%32]
		}

		return copy(p, raw[salamanderSaltLen:]), addr, nil
	}
}

func (c *salamanderConn) Close() error                       { return c.inner.Close() }
func (c *salamanderConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *salamanderConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *salamanderConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *salamanderConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// salamanderKey derives the XOR key for one salt.
func salamanderKey(psk, salt []byte) [32]byte {
	return blake2b.Sum256(append(append([]byte(nil), psk...), salt...))
}

// unwrap returns the underlying packet conn, used by tests that need to inject
// deliberately malformed datagrams.
func (c *salamanderConn) unwrap() net.PacketConn { return c.inner }
