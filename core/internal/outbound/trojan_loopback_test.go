package outbound

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"arc/core/internal/outbound/trojan"
	"arc/core/internal/store"
)

func trojanKey(password string) (key [trojan.KeyLength]byte) {
	sum := sha256.Sum224([]byte(password))
	hex.Encode(key[:], sum[:])
	return key
}

func trojanPlain(key [trojan.KeyLength]byte, payload string) []byte {
	return append(trojan.AppendHeader(nil, key, trojan.CommandTCP, appendAddr(nil, TargetAddr{Domain: "example.com", Port: 443})), payload...)
}

func leafCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"trojan.example"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func tlsServer(t *testing.T, protos []string) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{leafCert(t)},
		NextProtos:   protos,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func dialWrap(t *testing.T, addr string, opts *store.NodeOpts, prof *store.UpstreamProfile) net.Conn {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	if opts == nil {
		opts = &store.NodeOpts{}
	}
	opts.SkipCertVerify = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	c, err := wrapTrojan(ctx, raw, "trojan.example", opts, prof, trojan.CommandTCP, TargetAddr{Domain: "example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestTrojanLoopback(t *testing.T) {
	key := trojanKey("trojan-pass")
	expect := trojanPlain(key, "ping")
	prof := &store.UpstreamProfile{Proto: store.ProtoTrojan, Key: key[:]}
	ln := tlsServer(t, []string{"h2", "http/1.1"})
	got := make(chan []byte, 1)
	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		got <- readExactOK(conn, len(expect))
	}()
	c := dialWrap(t, ln.Addr().String(), nil, prof)
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		t.Fatal(err)
	case buf := <-got:
		if !bytes.Equal(buf, expect) {
			t.Fatalf("wire %x want %x", buf, expect)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func readExactOK(r io.Reader, n int) []byte {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return append([]byte("err:"), []byte(err.Error())...)
	}
	return buf
}
