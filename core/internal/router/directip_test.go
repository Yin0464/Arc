package router

import (
	"net/netip"
	"testing"
	"time"
)

func TestClearDirectIPs(t *testing.T) {
	a := netip.MustParseAddr("203.0.113.10")
	NoteDirectIP(a, time.Minute)
	if !IsDirectIP(a) {
		t.Fatal("note failed")
	}
	ClearDirectIPs()
	if IsDirectIP(a) {
		t.Fatal("clear failed")
	}
}

func TestDirectIPFullEvictsOne(t *testing.T) {
	dipMu.Lock()
	prev := dips
	dips = make(map[netip.Addr]int64, maxDirectIPs)
	exp := nowUnix() + 3600
	for i := 0; i < maxDirectIPs; i++ {
		dips[netip.AddrFrom4([4]byte{203, byte(i >> 16), byte(i >> 8), byte(i)})] = exp
	}
	dipMu.Unlock()
	t.Cleanup(func() {
		dipMu.Lock()
		dips = prev
		dipMu.Unlock()
	})
	extra := netip.MustParseAddr("203.0.113.50")
	NoteDirectIP(extra, time.Hour)
	if !IsDirectIP(extra) {
		t.Fatal("new direct ip missing")
	}
	dipMu.RLock()
	n := len(dips)
	dipMu.RUnlock()
	if n != maxDirectIPs {
		t.Fatalf("len=%d want %d", n, maxDirectIPs)
	}
	NoteDirectIP(extra, 2*time.Hour)
	dipMu.RLock()
	n = len(dips)
	dipMu.RUnlock()
	if n != maxDirectIPs {
		t.Fatalf("refresh len=%d", n)
	}
}
