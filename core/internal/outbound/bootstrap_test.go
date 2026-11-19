package outbound

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"arc/core/internal/dnswire"
)

// fakeTier1 serves A queries on loopback UDP: rcode 2 when fail is set,
// otherwise 127.0.0.1 with a 300s TTL.
func fakeTier1(t *testing.T, fail bool, hits *atomic.Int32) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 512)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			hits.Add(1)
			_, qt, qEnd, ok := dnswire.Question(b[:n])
			if !ok {
				continue
			}
			if fail {
				pc.WriteTo(dnswire.Answer(b[:n], qEnd, 2, 0, 0, nil), a)
				continue
			}
			pc.WriteTo(dnswire.Answer(b[:n], qEnd, 0, qt, 300, []byte{127, 0, 0, 1}), a)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func withTier1(t *testing.T, servers [2]netip.AddrPort) {
	old := BootstrapDNS
	BootstrapDNS = servers
	dohIPCache.Clear()
	t.Cleanup(func() { BootstrapDNS = old; dohIPCache.Clear() })
}

func TestDomesticDoHIsHostnameBootstrapped(t *testing.T) {
	for _, raw := range DomesticDoHUrls {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" {
			t.Fatalf("bad domestic DoH url %q", raw)
		}
		if _, err := netip.ParseAddr(u.Hostname()); err == nil {
			t.Fatalf("domestic DoH %q is an IP literal", raw)
		}
	}
	for _, s := range BootstrapDNS {
		if s.Port() != 53 || !s.Addr().Is4() {
			t.Fatalf("tier-1 server %v", s)
		}
	}
}

// A tier-2 hostname (domestic or private DoH) is resolved by tier 1 and the
// connection goes straight to that address; a failing tier-1 server loses
// the race instead of failing the lookup.
func TestDirectDoHDialUsesTier1(t *testing.T) {
	var good, bad atomic.Int32
	withTier1(t, [2]netip.AddrPort{fakeTier1(t, true, &bad), fakeTier1(t, false, &good)})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for range 2 {
		c, err := directDoHDial(ctx, "tcp", net.JoinHostPort("private-doh.test", port))
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if good.Load() != 1 {
		t.Fatalf("tier-1 queries %d, want 1 (second dial cached)", good.Load())
	}
}

func TestBootstrapServesStaleOnTier1Failure(t *testing.T) {
	var hits atomic.Int32
	withTier1(t, [2]netip.AddrPort{fakeTier1(t, true, &hits), fakeTier1(t, true, &hits)})
	gen := flowGen.Load()
	ip := netip.MustParseAddr("203.0.113.9")
	dohIPCache.Store("stale.test", dohIP{gen, ip, time.Now().Add(-time.Minute)})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := resolveBootstrapHost(ctx, "stale.test", gen)
	if err != nil || got != ip {
		t.Fatalf("stale not served: %v %v", got, err)
	}
	dohIPCache.Store("stale.test", dohIP{gen, ip, time.Now().Add(-time.Minute - bootstrapStale)})
	if _, err := resolveBootstrapHost(ctx, "stale.test", gen); err == nil {
		t.Fatal("too-stale address served")
	}
	if _, err := resolveBootstrapHost(ctx, "fresh.test", gen); err == nil {
		t.Fatal("tier-1 failure resolved a name")
	}
}

func TestBootstrapIgnoresOldGeneration(t *testing.T) {
	pendingClears.Wait()
	const host = "bootstrap.example"
	t.Cleanup(func() { dohIPCache.Delete(host) })
	ip := netip.MustParseAddr("203.0.113.9")
	gen := flowGen.Load()
	storeDoHIP(host, ip, 1, gen)
	if e, ok := loadDoHIP(host, flowGen.Load()); !ok || e.ip != ip || time.Until(e.expires) < 59*time.Second {
		t.Fatalf("cached %v %v", e, ok)
	}
	CloseLiveConns()
	if _, ok := loadDoHIP(host, flowGen.Load()); ok {
		t.Fatal("old generation still used")
	}
	dohIPCache.Delete(host)
	storeDoHIP(host, ip, 300, gen)
	if _, ok := dohIPCache.Load(host); ok {
		t.Fatal("late store of the old generation was accepted")
	}
}

// The pre-check resolver is a hostname: the node resolves and dials it, so
// neither its address nor a local lookup of it is involved.
func TestRemoteDoHIsHostnameThroughNode(t *testing.T) {
	for _, raw := range RemoteDoHUrls {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" {
			t.Fatalf("bad pre-check url %q", raw)
		}
		if _, err := netip.ParseAddr(u.Hostname()); err == nil {
			t.Fatalf("pre-check DoH %q is an IP literal", raw)
		}
	}
}
