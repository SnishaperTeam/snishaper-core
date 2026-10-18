package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestVerifyChainOnlyRejectsEmptyChain(t *testing.T) {
	if err := VerifyChainOnly(nil); err == nil {
		t.Fatal("expected error for empty certificate chain")
	}
}

func TestVerifyChainOnlyRejectsSelfSigned(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "self-signed.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChainOnly([]*x509.Certificate{cert}); err == nil {
		t.Fatal("expected self-signed certificate to be rejected")
	}
}

func TestMapNAT64Addr(t *testing.T) {
	if got, ok := MapNAT64Addr("1.2.3.4", ""); got != "1.2.3.4" || !ok {
		t.Fatalf("empty prefix: got %q ok=%v", got, ok)
	}
	got, ok := MapNAT64Addr("192.0.2.1", "64:ff9b::/96")
	if !ok {
		t.Fatal("expected mapping success")
	}
	if got != "64:ff9b::c000:201" {
		t.Fatalf("unexpected NAT64 mapping: %q", got)
	}
	if got, ok := MapNAT64Addr("2001:db8::1", "64:ff9b::/96"); got != "2001:db8::1" || ok {
		t.Fatalf("ipv6 input should pass through unchanged, got %q ok=%v", got, ok)
	}
	if got, _ := MapNAT64Addr("example.com", "64:ff9b::/96"); got != "example.com" {
		t.Fatalf("hostname should pass through, got %q", got)
	}
}

func TestHalfCloseTCPConn(t *testing.T) {
	client, server := newTCPPair(t)
	defer client.Close()
	defer server.Close()
	HalfClose(client)
	buf := make([]byte, 1)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := server.Read(buf); err == nil {
		t.Fatal("expected EOF after HalfClose")
	}
}

func newTCPPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		ch <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server = <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("accept timeout")
	}
	return client, server
}
