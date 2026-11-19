package udpnat

import (
	"net/netip"
	"testing"
	"time"
)

func seed(m *Manager, last int64, srcs ...netip.AddrPort) map[netip.AddrPort]*udpSession {
	out := map[netip.AddrPort]*udpSession{}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, src := range srcs {
		s := newUDPSession(nil, true, false, netip.MustParseAddrPort("9.9.9.9:53"))
		s.lastActive.Store(last)
		m.sessions[natKey{src, natDirect}] = s
		out[src] = s
	}
	return out
}

func TestEvictIdleKeepsHotSessions(t *testing.T) {
	m := New()
	defer m.ClearAll()
	now := time.Now().Unix()
	hot := netip.MustParseAddrPort("10.9.0.1:40001")
	seed(m, now, hot)
	seed(m, now-60, netip.MustParseAddrPort("10.9.0.2:40002"))
	if n := m.EvictIdle(SessionLimit, 15); n != 1 {
		t.Fatalf("evicted %d, want 1", n)
	}
	m.mu.Lock()
	_, alive := m.sessions[natKey{hot, natDirect}]
	left := len(m.sessions)
	m.mu.Unlock()
	if left != 1 || !alive {
		t.Fatalf("soft evict must keep hot sessions, left=%d hot=%v", left, alive)
	}
}

func TestEvictIdleBoundedByMax(t *testing.T) {
	m := New()
	defer m.ClearAll()
	now := time.Now().Unix()
	for i := 0; i < 8; i++ {
		seed(m, now-60, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 2, 0, byte(i)}), uint16(30000+i)))
	}
	if n := m.EvictIdle(3, 15); n != 3 {
		t.Fatalf("evicted %d, want 3", n)
	}
}

func TestClearAllDropsEverySession(t *testing.T) {
	m := New()
	seed(m, time.Now().Unix(), netip.MustParseAddrPort("10.9.1.1:40101"))
	m.ClearAll()
	m.mu.Lock()
	n := len(m.sessions)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("ClearAll left %d", n)
	}
}

// EvictIdle removes the longest-idle sessions first.
func TestEvictIdleOldestFirst(t *testing.T) {
	m := New()
	defer m.ClearAll()
	now := time.Now().Unix()
	ap := func(i int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 3, 0, byte(i)}), uint16(31000+i))
	}
	for i := 0; i < 10; i++ {
		seed(m, now-int64(20+i*10), ap(i))
	}
	if n := m.EvictIdle(4, 15); n != 4 {
		t.Fatalf("evicted %d, want 4", n)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 0; i < 10; i++ {
		if _, alive := m.sessions[natKey{ap(i), natDirect}]; alive != (i < 6) {
			t.Fatalf("session idle %ds alive=%v", 20+i*10, alive)
		}
	}
}
