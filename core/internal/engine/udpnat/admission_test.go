package udpnat

import (
	"net/netip"
	"testing"
	"time"
)

func TestUDPAdmissionEvictsLongestIdle(t *testing.T) {
	m := New()
	defer m.ClearAll()
	now := time.Now().Unix()
	makeSess := func(src string, idleAgo int64) *udpSession {
		s := newUDPSession(nil, true, false, netip.MustParseAddrPort("1.1.1.1:53"))
		s.lastActive.Store(now - idleAgo)
		m.mu.Lock()
		m.sessions[natKey{netip.MustParseAddrPort(src), natDirect}] = s
		m.mu.Unlock()
		return s
	}
	for i := 0; i < SessionLimit; i++ {
		idle := int64(1)
		if i == 7 {
			idle = 60
		} else if i == 3 {
			idle = 20
		}
		makeSess(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), uint16(10000+i)).String(), idle)
	}
	idlest := m.sessions[natKey{netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 7}), 10007), natDirect}]
	m.mu.Lock()
	victim, ok := m.admitOrEvictLocked()
	m.mu.Unlock()
	if !ok || victim != idlest {
		t.Fatalf("ok=%v victim=%v want idlest", ok, victim != nil)
	}
	if _, still := m.sessions[natKey{netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 7}), 10007), natDirect}]; still {
		t.Fatal("victim not removed")
	}
	victim.stop()
}

func TestUDPAdmissionRejectsWhenNothingIdle(t *testing.T) {
	m := New()
	defer m.ClearAll()
	now := time.Now().Unix()
	for i := 0; i < SessionLimit; i++ {
		s := newUDPSession(nil, true, false, netip.MustParseAddrPort("1.1.1.1:443"))
		s.lastActive.Store(now)
		m.mu.Lock()
		m.sessions[natKey{netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}), uint16(20000+i)), natDirect}] = s
		m.mu.Unlock()
	}
	m.mu.Lock()
	victim, ok := m.admitOrEvictLocked()
	m.mu.Unlock()
	if ok || victim != nil {
		t.Fatal("should reject when nothing idle")
	}
	if len(m.sessions) != SessionLimit {
		t.Fatal("reject must not drop sessions")
	}
}

func TestSessionLimitConstant(t *testing.T) {
	if SessionLimit < 128 || SessionLimit > 1024 {
		t.Fatalf("SessionLimit=%d out of sensible Android range", SessionLimit)
	}
}
