package engine

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"arc/core/internal/dns"
	"arc/core/internal/dnswire"
	"arc/core/internal/engine/udpnat"
	"arc/core/internal/router"
)

func TestCNNameOnGoogleIPIsNotDirect(t *testing.T) {
	g := netip.MustParseAddr("142.250.72.196")
	if !router.IsGoogleIP(g) {
		t.Skip("sample not in Google table")
	}
	if cnNameDirect("www.baidu.com", g) {
		t.Fatal("Google IP must outrank a CN SNI")
	}
	if !cnNameDirect("www.baidu.com", netip.MustParseAddr("43.175.44.34")) {
		t.Fatal("CN SNI on a non-Google IP should stay direct")
	}
}

func TestOrphanFakeAddressRefused(t *testing.T) {
	m := udpnat.New()
	src := netip.MustParseAddrPort("172.19.0.1:41000")
	for _, a := range []string{"198.18.250.250", "fdfe:dcba:9876:ff::fafa"} {
		ip := netip.MustParseAddr(a)
		if _, ok := dns.GlobalFakeIP.Lookup(ip); ok {
			t.Skip("slot allocated")
		}
		if !dns.InFakeRange(ip) {
			t.Fatalf("%s should be in fake range", a)
		}
		if !m.ForwardPacket(src, netip.AddrPortFrom(ip, 5000), []byte("x"), func([]byte, netip.AddrPort) {}) {
			t.Fatalf("UDP to orphan %s not refused", a)
		}
	}
	c1, c2 := pipePair(t)
	defer c2.Close()
	start := time.Now()
	HandleInboundTCP(context.Background(), c1, netip.MustParseAddrPort("198.18.250.250:443"))
	if time.Since(start) > time.Second {
		t.Fatal("orphan fake TCP should fail fast")
	}
}

func TestFakeNowDirectUDPRefused(t *testing.T) {
	ip := dns.GlobalFakeIP.Allocate("www.baidu.com", false)
	m := udpnat.New()
	if !m.ForwardPacket(netip.MustParseAddrPort("172.19.0.1:41001"), netip.AddrPortFrom(ip, 443), []byte("x"), func([]byte, netip.AddrPort) {}) {
		t.Fatal("fake IP of a direct name must be refused for UDP")
	}
}

func pipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	return a, b
}

func TestFakeNowDirectTCPRoutesByName(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	prev := lookupDirect
	lookupDirect = func(_ context.Context, host string, qt uint16) []netip.Addr {
		if host == "www.baidu.com" && qt == dnswire.TypeA {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		}
		return nil
	}
	defer func() { lookupDirect = prev }()
	got := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			got <- struct{}{}
			c.Close()
		}
	}()
	ip := dns.GlobalFakeIP.Allocate("www.baidu.com", false)
	c1, c2 := pipePair(t)
	done := make(chan struct{})
	go func() { HandleInboundTCP(context.Background(), c1, netip.AddrPortFrom(ip, port)); close(done) }()
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Error("direct name behind fake IP was not dialed directly")
	}
	c2.Close()
	<-done
}
