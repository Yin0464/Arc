package engine

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDirectV6FallbackToV4(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("ok"))
			c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	old := lookupDirect
	defer func() { lookupDirect = old }()
	var asked string
	lookupDirect = func(ctx context.Context, d string, qt uint16) []netip.Addr {
		asked = d
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}

	dst := netip.AddrPortFrom(netip.MustParseAddr("100::1"), port)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := dialDirectFallback(ctx, dst, "m.client.10010.com")
	if err != nil {
		t.Fatalf("fallback failed: %v", err)
	}
	b := make([]byte, 2)
	n, _ := c.Read(b)
	c.Close()
	if string(b[:n]) != "ok" || asked != "m.client.10010.com" {
		t.Fatalf("got %q asked %q", b[:n], asked)
	}

	if _, err := dialDirectFallback(ctx, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 1), "x.cn"); err == nil {
		t.Fatal("want error")
	}
}
