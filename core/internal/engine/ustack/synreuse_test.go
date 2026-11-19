package ustack

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func synReuseStack(t *testing.T) (*Stack, tcpKey, *tcpConn) {
	t.Helper()
	u := New(Config{
		Send:     func([]byte, *[]byte) {},
		Alive:    func() bool { return true },
		LateBind: func(netip.AddrPort) bool { return false },
	})
	t.Cleanup(u.Close)
	key := tcpKey{remote: netip.MustParseAddrPort("10.0.0.2:5555"), local: netip.MustParseAddrPort("10.0.0.9:80")}
	u.handleSYN(key, 0, 1000, 65535, []byte{2, 4, 0x05, 0xb4}, 80)
	u.mu.Lock()
	old := u.conns[key]
	u.mu.Unlock()
	if old == nil {
		t.Fatal("first SYN created no conn")
	}
	return u, key, old
}

func connAt(u *Stack, key tcpKey) *tcpConn {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conns[key]
}

func toTimeWait(c *tcpConn, rcvNxt uint32) {
	c.mu.Lock()
	c.state = stTimeWait
	c.timeWait = time.Now()
	c.unacked = nil
	c.rcvNxt = rcvNxt
	c.mu.Unlock()
}

func TestSYNHigherISNReopensTimeWait(t *testing.T) {
	u, key, old := synReuseStack(t)
	toTimeWait(old, 5000)
	u.handleSYN(key, 0, 9000, 65535, []byte{2, 4, 0x05, 0xb4}, 80)
	c := connAt(u, key)
	if c == nil || c == old {
		t.Fatal("higher-ISN SYN did not take over the TIME-WAIT slot")
	}
	if c.state != stSynRcvd || c.irs != 9000 {
		t.Fatalf("new conn state=%v irs=%d", c.state, c.irs)
	}
	old.mu.Lock()
	st := old.state
	old.mu.Unlock()
	if st != stClosed {
		t.Fatalf("old conn state=%v, want closed", st)
	}
	time.Sleep(20 * time.Millisecond) // old's async remove must not evict the new conn
	if connAt(u, key) != c {
		t.Fatal("new conn evicted by old conn's remove")
	}
}

// challengeStack is synReuseStack with the emitted TCP segments captured.
func challengeStack(t *testing.T) (*Stack, tcpKey, *tcpConn, func() [][]byte) {
	t.Helper()
	var mu sync.Mutex
	var out [][]byte
	u := New(Config{
		Send: func(p []byte, _ *[]byte) {
			mu.Lock()
			out = append(out, append([]byte(nil), p...))
			mu.Unlock()
		},
		Alive:    func() bool { return true },
		LateBind: func(netip.AddrPort) bool { return false },
	})
	t.Cleanup(u.Close)
	key := tcpKey{remote: netip.MustParseAddrPort("10.0.0.2:5555"), local: netip.MustParseAddrPort("10.0.0.9:80")}
	u.handleSYN(key, 0, 1000, 65535, []byte{2, 4, 0x05, 0xb4}, 80)
	old := connAt(u, key)
	if old == nil {
		t.Fatal("first SYN created no conn")
	}
	return u, key, old, func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		r := out
		out = nil
		return r
	}
}

// wantChallengeACK checks that exactly one pure ACK <SEQ=sndNxt><ACK=rcvNxt> went out.
func wantChallengeACK(t *testing.T, sent [][]byte, c *tcpConn) {
	t.Helper()
	if len(sent) != 1 {
		t.Fatalf("sent %d segments, want 1 challenge ACK", len(sent))
	}
	tcp := sent[0][20:]
	c.mu.Lock()
	seq, ack := c.sndNxt, c.rcvNxt
	c.mu.Unlock()
	if tcp[13] != 0x10 || binary.BigEndian.Uint32(tcp[4:8]) != seq || binary.BigEndian.Uint32(tcp[8:12]) != ack {
		t.Fatalf("flags=%#x seq=%d ack=%d, want ACK seq=%d ack=%d", tcp[13],
			binary.BigEndian.Uint32(tcp[4:8]), binary.BigEndian.Uint32(tcp[8:12]), seq, ack)
	}
}

func TestSYNLowerISNChallengeACKInTimeWait(t *testing.T) {
	u, key, old, sent := challengeStack(t)
	toTimeWait(old, 5000)
	sent()
	u.handleSYN(key, 0, 4000, 65535, []byte{2, 4, 0x05, 0xb4}, 80)
	if connAt(u, key) != old {
		t.Fatal("lower-ISN SYN replaced the TIME-WAIT conn")
	}
	old.mu.Lock()
	st := old.state
	old.mu.Unlock()
	if st != stTimeWait {
		t.Fatalf("old conn state=%v", st)
	}
	wantChallengeACK(t, sent(), old)
}

func TestSYNChallengeACKInEstablished(t *testing.T) {
	u, key, old, sent := challengeStack(t)
	old.mu.Lock()
	old.state = stEstablished
	old.unacked = nil
	old.handed = true
	old.mu.Unlock()
	sent()
	u.handleSYN(key, 0, 7000, 65535, []byte{2, 4, 0x05, 0xb4}, 80)
	if connAt(u, key) != old {
		t.Fatal("SYN replaced the established conn")
	}
	wantChallengeACK(t, sent(), old)
}

func TestSYNIgnoredWhileLateBindPending(t *testing.T) {
	u, key, old, sent := challengeStack(t)
	old.mu.Lock()
	old.latePending = true
	old.unacked = nil
	old.mu.Unlock()
	sent()
	u.handleSYN(key, 0, 1000, 65535, []byte{2, 4, 0x05, 0xb4}, 80)
	if got := sent(); len(got) != 0 {
		t.Fatalf("sent %d segments before the late SYN-ACK", len(got))
	}
}

func TestSYNTakesOverClosedSlot(t *testing.T) {
	u, key, old := synReuseStack(t)
	old.mu.Lock()
	old.state = stClosed // closed, async remove still pending
	old.unacked = nil
	old.mu.Unlock()
	u.handleSYN(key, 0, 2000, 65535, []byte{2, 4, 0x05, 0xb4}, 80)
	c := connAt(u, key)
	if c == nil || c == old || c.irs != 2000 {
		t.Fatal("SYN did not take over a closed, not-yet-removed slot")
	}
}

// TestKeepAliveProbeACKed: an empty segment at rcvNxt-1 (a keep-alive probe)
// gets one ACK in Established and CloseWait; in-window pure ACKs get none.
func TestKeepAliveProbeACKed(t *testing.T) {
	for _, st := range []uint8{stEstablished, stCloseWait} {
		_, _, c, sent := challengeStack(t)
		c.mu.Lock()
		c.state = st
		c.unacked = nil
		c.handed = true
		c.sndUna = c.sndNxt
		rn, sn := c.rcvNxt, c.sndNxt
		c.mu.Unlock()
		sent()
		c.handleSeg(rn-1, sn, 0x10, 65535, nil, nil)
		wantChallengeACK(t, sent(), c)
		for _, seq := range []uint32{rn, rn + 100} {
			c.handleSeg(seq, sn, 0x10, 65535, nil, nil)
			if got := sent(); len(got) != 0 {
				t.Fatalf("state %d: pure ACK seq=rcvNxt%+d answered with %d segments", st, int32(seq-rn), len(got))
			}
		}
	}
}
