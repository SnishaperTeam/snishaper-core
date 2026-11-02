package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestDefaultUpstreamCertVerify(t *testing.T) {
	cases := []struct {
		name string
		sni  string
		host string
		want string
	}{
		{"no fake sni verifies hostname", "", "example.com", "strict_real"},
		{"fake sni equal to host verifies hostname", "example.com", "example.com", "strict_real"},
		{"fake sni differing falls back to chain only", "front.example", "example.com", "chain_only"},
		{"case and dot differences are ignored", "Example.COM.", "example.com", "strict_real"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := defaultUpstreamCertVerify(Rule{SniFake: c.sni}, c.host)
			if got.Mode != c.want {
				t.Fatalf("mode = %q, want %q", got.Mode, c.want)
			}
		})
	}
}

func selfSignedFor(t *testing.T, dnsName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestDefaultVerificationRejectsForeignHostname(t *testing.T) {
	verify := buildVerifyConnection("example.com", defaultUpstreamCertVerify(Rule{}, "example.com"))
	if verify == nil {
		t.Fatal("default rule produced no verification callback")
	}

	wrong := selfSignedFor(t, "attacker.example")
	err := verify(utls.ConnectionState{PeerCertificates: []*x509.Certificate{wrong}})
	if err == nil {
		t.Fatal("a certificate for another host was accepted for example.com")
	}

	right := selfSignedFor(t, "example.com")
	err = verify(utls.ConnectionState{PeerCertificates: []*x509.Certificate{right}})
	if err != nil {
		var unknown x509.UnknownAuthorityError
		if !asError(err, &unknown) {
			t.Fatalf("matching certificate rejected for the wrong reason: %v", err)
		}
	}
}

func asError(err error, target *x509.UnknownAuthorityError) bool {
	unknown, ok := err.(x509.UnknownAuthorityError)
	if ok {
		*target = unknown
	}
	return ok
}
