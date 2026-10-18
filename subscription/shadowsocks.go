package subscription

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	ssTagSize       = 16
	ssMaxPayloadLen = 0x3FFF
	// maxPayloadWithLength is the largest plaintext chunk: the 2-byte length
	// field must fit inside the 0x3FFF limit.
	ssMaxPayloadWithLength = ssMaxPayloadLen

	defaultDialTimeout = 10 * time.Second
)

// aeadFactory builds an AEAD from a derived subkey.
type aeadFactory func(key []byte) (cipher.AEAD, error)

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newChaCha(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// shadowsocksSpec describes one supported Shadowsocks AEAD cipher.
type shadowsocksSpec struct {
	keySize  int
	saltSize int
	factory  aeadFactory
	// chacha selects the 12-byte nonce construction; AES-GCM uses the
	// standard nonce size returned by the AEAD itself.
	chacha bool
}

var shadowsocksSpecs = map[string]shadowsocksSpec{
	"aes-128-gcm":             {16, 16, newAESGCM, false},
	"aes-192-gcm":             {24, 24, newAESGCM, false},
	"aes-256-gcm":             {32, 32, newAESGCM, false},
	"chacha20-ietf-poly1305":  {32, 32, newChaCha, true},
	"xchacha20-ietf-poly1305": {32, 32, newChaCha, true},
}

func lookupShadowsocksSpec(name string) (shadowsocksSpec, bool) {
	spec, ok := shadowsocksSpecs[strings.ToLower(strings.TrimSpace(name))]
	return spec, ok
}

// shadowsocksKey derives the legacy EVP_BytesToKey MD5 key used for the
// initial salt and the HKDF master secret.
func shadowsocksKey(password string, keyLen int) []byte {
	out := make([]byte, 0, keyLen)
	var digest []byte
	for len(out) < keyLen {
		h := md5.New()
		h.Write(digest)
		h.Write([]byte(password))
		digest = h.Sum(nil)
		out = append(out, digest...)
	}
	return out[:keyLen]
}

func hkdfSHA1(secret, salt, info []byte, length int) ([]byte, error) {
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.New(sha1.New, secret, salt, info), out); err != nil {
		return nil, err
	}
	return out, nil
}

func hkdfSHA1NoErr(secret, salt, info []byte, length int) []byte {
	out, err := hkdfSHA1(secret, salt, info, length)
	if err != nil {
		return make([]byte, length)
	}
	return out
}

// shadowsocksConn speaks the Shadowsocks 2022 AEAD transport (AEAD-2022
// ciphers only). Legacy stream ciphers are not supported.
type shadowsocksConn struct {
	net.Conn

	spec    shadowsocksSpec
	session []byte // HKDF-SHA1 master key
	nonce   uint64

	readBuf []byte
	readPos int
	reader  *bufio.Reader
}

func dialShadowsocks(cipherName, password, serverAddr, network string) (net.Conn, error) {
	spec, ok := lookupShadowsocksSpec(cipherName)
	if !ok {
		return nil, fmt.Errorf("unsupported shadowsocks cipher %q", cipherName)
	}
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("shadowsocks password is required")
	}

	host, port := SplitHostPort(serverAddr, 8388)
	rawConn, err := net.DialTimeout(network, net.JoinHostPort(host, fmt.Sprint(port)), defaultDialTimeout)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, spec.saltSize)
	if _, err := rand.Read(salt); err != nil {
		rawConn.Close()
		return nil, err
	}

	sessionKey := shadowsocksKey(password, spec.keySize)
	session, err := hkdfSHA1(sessionKey, salt, []byte("ss-subkey"), spec.keySize)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	if _, err := rawConn.Write(salt); err != nil {
		rawConn.Close()
		return nil, err
	}

	return &shadowsocksConn{
		Conn:    rawConn,
		spec:    spec,
		session: session,
	}, nil
}

// AEAD-2022 spec detail: the length chunk and the payload chunk of one frame
// use different nonces and different subkeys. nextPayloadNonce reads the
// counter AFTER nextNonce has incremented it, so for chunk k the payload nonce
// counter is k+1+0x10000; the masking HKDF and both chunk keys are derived
// from the first 8 bytes of their respective nonces.
const ssPayloadNonceOffset = 0x10000

func (c *shadowsocksConn) newAEADWithNonce(nonce []byte) (cipher.AEAD, error) {
	key := hkdfSHA1NoErr(c.session, nonce[:8], []byte("ss-chunk"), len(c.session))
	return c.spec.factory(key)
}

func (c *shadowsocksConn) nextNonce() [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.nonce)
	c.nonce++
	return nonce
}

func (c *shadowsocksConn) nextPayloadNonce() [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.nonce+ssPayloadNonceOffset)
	return nonce
}

func (c *shadowsocksConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		size := len(p)
		if size > ssMaxPayloadLen {
			size = ssMaxPayloadLen
		}
		chunk := p[:size]
		p = p[size:]

		out, err := c.sealFrame(chunk)
		if err != nil {
			return written, err
		}
		if _, err := c.Conn.Write(out); err != nil {
			return written, err
		}
		written += size
	}
	return written, nil
}

// sealFrame encrypts one frame as two separately keyed chunks: the masked
// length, then the masked payload.
func (c *shadowsocksConn) sealFrame(payload []byte) ([]byte, error) {
	length := len(payload)

	// Length chunk, nonce = counter.
	lenNonce := c.nextNonce()
	lenAEAD, err := c.newAEADWithNonce(lenNonce[:])
	if err != nil {
		return nil, err
	}
	mask := hkdfSHA1NoErr(c.session, lenNonce[:8], []byte("ss-mask"), 2)
	lenPlain := []byte{byte(length>>8) ^ mask[0], byte(length) ^ mask[1]}
	lenSealed := lenAEAD.Seal(nil, lenNonce[:], lenPlain, nil)

	// Payload chunk, nonce = counter + 0x10000.
	payNonce := c.nextPayloadNonce()
	payAEAD, err := c.newAEADWithNonce(payNonce[:])
	if err != nil {
		return nil, err
	}
	payPlain := make([]byte, length)
	for i := 0; i < length; i++ {
		payPlain[i] = payload[i] ^ mask[i%2]
	}
	paySealed := payAEAD.Seal(nil, payNonce[:], payPlain, nil)

	out := make([]byte, 0, len(lenSealed)+len(paySealed))
	out = append(out, lenSealed...)
	out = append(out, paySealed...)
	return out, nil
}

func (c *shadowsocksConn) Read(p []byte) (int, error) {
	for c.readPos >= len(c.readBuf) {
		if err := c.readChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.readBuf[c.readPos:])
	c.readPos += n
	return n, nil
}

func (c *shadowsocksConn) readChunk() error {
	// A Shadowsocks AEAD frame is:
	//   [ encrypted length (2) | length tag (16) | payload | payload tag (16) ]
	// The payload length is masked, so the header must be decrypted first to
	// learn the total frame size. That makes a two-step read exact, which
	// avoids guessing frame boundaries on a stream socket.
	if c.reader == nil {
		c.reader = bufio.NewReaderSize(c.Conn, 64*1024)
	}

	nonce := c.nextNonce()
	aead, err := c.newAEADWithNonce(nonce[:])
	if err != nil {
		return err
	}

	header := make([]byte, 2+ssTagSize)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return err
	}

	plain, err := aead.Open(nil, nonce[:], header, nil)
	if err != nil {
		return fmt.Errorf("shadowsocks: header decrypt failed: %w", err)
	}
	if len(plain) != 2 {
		return fmt.Errorf("shadowsocks: bad header length %d", len(plain))
	}

	mask := hkdfSHA1NoErr(c.session, nonce[:8], []byte("ss-mask"), 2)
	length := int(plain[0]^mask[0])<<8 | int(plain[1]^mask[1])
	if length <= 0 || length > ssMaxPayloadLen {
		return fmt.Errorf("shadowsocks: invalid payload length %d", length)
	}

	body := make([]byte, length+ssTagSize)
	if _, err := io.ReadFull(c.reader, body); err != nil {
		return err
	}

	payNonce := c.nextPayloadNonce()
	payAEAD, err := c.newAEADWithNonce(payNonce[:])
	if err != nil {
		return err
	}
	bodyPlain, err := payAEAD.Open(nil, payNonce[:], body, nil)
	if err != nil {
		return fmt.Errorf("shadowsocks: payload decrypt failed: %w", err)
	}
	if len(bodyPlain) != length {
		return fmt.Errorf("shadowsocks: payload length mismatch %d != %d", len(bodyPlain), length)
	}

	payload := make([]byte, length)
	for i := 0; i < length; i++ {
		payload[i] = bodyPlain[i] ^ mask[i%2]
	}

	c.readBuf = payload
	c.readPos = 0
	return nil
}
