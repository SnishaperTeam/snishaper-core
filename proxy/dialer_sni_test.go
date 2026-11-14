package proxy

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestEstablishUpstreamConnUsesComputedSNI guards against the 1.28 refactor
// regression (issue SnishaperTeam/SniShaper#191): the TCP MITM dial path passed
// the raw rule.SniFake to GetUConn instead of the SNI computed by
// chooseUpstreamSNI. For sni_policy=fake rules with an empty sni_fake that
// leaked the real hostname as upstream SNI, letting GFW reset the connection.
func TestEstablishUpstreamConnUsesComputedSNI(t *testing.T) {
	cert, key := selfSignedCert(t, "sni-probe")
	tlsCert := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}

	sniCh := make(chan string, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case sniCh <- hi.ServerName:
			default:
			}
			return nil, nil
		},
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tlsConn := tls.Server(c, cfg)
				_ = tlsConn.Handshake()
				_ = tlsConn.Close()
			}()
		}
	}()

	p := NewProxyServer("127.0.0.1:0")
	rule := Rule{Mode: "mitm", SniPolicy: "fake"} // SniFake intentionally empty
	// Handshake error is expected (self-signed upstream fails strict_real);
	// the assertion is which SNI reached the wire.
	_, _, _ = p.EstablishUpstreamConn("www.example.com", rule, []string{ln.Addr().String()}, "http/1.1")

	select {
	case got := <-sniCh:
		if got != "www-example-com" {
			t.Fatalf("expected token SNI www-example-com on the wire, got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no ClientHello reached the upstream")
	}
}
