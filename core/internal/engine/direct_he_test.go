package engine

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"arc/core/internal/dnswire"
)

func TestDialDirectNameParallelHE(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()

	var aCalls, aaaaCalls atomic.Int32
	oldLookup := lookupDirect
	defer func() { lookupDirect = oldLookup }()
	lookupDirect = func(ctx context.Context, host string, qt uint16) []netip.Addr {
		switch qt {
		case dnswire.TypeA:
			aCalls.Add(1)
			select {
			case <-time.After(400 * time.Millisecond):
			case <-ctx.Done():
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		case dnswire.TypeAAAA:
			aaaaCalls.Add(1)
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	c, err := dialDirectName(ctx, "he.example", port)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if aCalls.Load() == 0 {
		t.Fatal("A lookup not started")
	}
	if aaaaCalls.Load() == 0 {
		t.Fatal("AAAA lookup not started after HE delay")
	}
	if elapsed < 200*time.Millisecond {
		t.Fatalf("expected HE delay before AAAA win, elapsed=%v", elapsed)
	}
	if elapsed > 900*time.Millisecond {
		t.Fatalf("dial too slow: %v", elapsed)
	}
	if directNameHEDelay != 250*time.Millisecond {
		t.Fatalf("directNameHEDelay=%v", directNameHEDelay)
	}
}
