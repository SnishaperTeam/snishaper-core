package subscription

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func makeSelfSigned() ([]byte, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"example.com", "target.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// trojanEchoServer speaks the server side of Trojan: the password exchange
// shadowsocksEchoServer implements the server side of the Shadowsocks AEAD
// transport so the client can be exercised for real.
func shadowsocksEchoServer(t *testing.T, key []byte, cipherName, password string) (addr string, stop func()) {
	t.Helper()
	spec, ok := lookupShadowsocksSpec(cipherName)
	if !ok {
		t.Fatalf("unknown cipher %q", cipherName)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	sessionKey := shadowsocksKey(password, spec.keySize)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				handleShadowsocksEcho(c, spec, sessionKey)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func handleShadowsocksEcho(conn net.Conn, spec shadowsocksSpec, sessionKey []byte) {
	salt := make([]byte, spec.saltSize)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return
	}

	session, err := hkdfSHA1(sessionKey, salt, []byte("ss-subkey"), spec.keySize)
	if err != nil {
		return
	}

	ss := &shadowsocksConn{session: session, spec: spec, Conn: conn}

	// The first frame carries the target address; every frame after it is
	// payload to echo back. Frames may be coalesced by TCP, so decode
	// repeatedly until a non-address frame arrives.
	if err := ss.readChunk(); err != nil {
		return
	}
	if _, err := ReadSocks5AddrBody(strings.NewReader(string(ss.readBuf))); err != nil {
		// Not an address frame: treat it as payload.
		line := strings.TrimSpace(string(ss.readBuf))
		ss.Write([]byte(toUpper(line) + " "))
		return
	}

	for {
		if err := ss.readChunk(); err != nil {
			return
		}
		if len(ss.readBuf) == 0 {
			return
		}
		line := strings.TrimSpace(string(ss.readBuf))
		ss.Write([]byte(toUpper(line) + " "))
		return
	}
}

func toUpper(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'a' && out[i] <= 'z' {
			out[i] -= 32
		}
	}
	return string(out)
}

// vmessEchoServer implements the server side of the VMess AEAD handshake so the
// client can be verified end to end.
func vmessEchoServer(t *testing.T, cert tls.Certificate, useTLS bool) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if useTLS {
					tlsConn := tls.Server(c, &tls.Config{
						Certificates: []tls.Certificate{cert},
						MinVersion:   tls.VersionTLS12,
					})
					if err := tlsConn.Handshake(); err != nil {
						return
					}
					handleVmessEcho(tlsConn)
					return
				}
				handleVmessEcho(c)
			}(raw)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func handleVmessEcho(conn net.Conn) {
	// Request: LEN(2) AUTH(16) SEALED(...) NONCE(12)
	head := make([]byte, 18)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	length := int(binary.BigEndian.Uint16(head[:2]))

	sealed := make([]byte, length)
	if _, err := io.ReadFull(conn, sealed); err != nil {
		return
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(conn, nonce); err != nil {
		return
	}

	// A real server derives the auth key from the user's UUID; the test client
	// uses a fixed one. ChaCha20-Poly1305 needs the full 32-byte key.
	uuid, err := parseUUID(testVMessUUID)
	if err != nil {
		return
	}
	key := make([]byte, 32)
	copy(key[:16], uuid[:])

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return
	}
	if _, err := aead.Open(nil, nonce, sealed, nil); err != nil {
		return
	}

	// The client only validates the 4-byte response header.
	resp := make([]byte, 4)
	resp[0] = uuid[0]
	resp[2] = 0x01
	conn.Write(resp)
}

const testVMessUUID = "11111111-2222-3333-4444-555555555555"

// testContext returns a context bounded by the test deadline.
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func trimLine(s string) string {
	return strings.TrimRight(strings.TrimRight(s, "\n"), "\r")
}
