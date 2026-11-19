package ustack

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"arc/core/internal/engine/tun"
)

func newTestConn(send func(pkt []byte)) *tcpConn {
	st := &Stack{cfg: Config{Send: func(pkt []byte, p *[]byte) {
		if send != nil {
			send(pkt)
		}
		tun.Packet{Pkt: pkt, Pooled: p}.Release()
	}}, kickCh: make(chan struct{}, 1)}
	st.fast.Store(true)
	return &tcpConn{
		st: st, fam: 0, state: stEstablished, mss: usDefaultMSS,
		localAP:  netip.MustParseAddrPort("10.0.0.1:443"),
		remoteAP: netip.MustParseAddrPort("10.0.0.2:50000"),
		rwait:    make(chan struct{}, 1), swait: make(chan struct{}, 1),
		lastRx: time.Now(), rto: usRTOMin, sndUna: 5000, sndNxt: 5000, rcvNxt: 1, rcvWnd: usRcvBuf,
		cwnd: usSndBuf, ssthresh: usSndBuf, sndWnd: 1 << 20,
	}
}

// With a zero peer window and data pending, the sender probes with an ACK
// at sndUna-1 (RFC 9293 3.8.6.1) and does not keep the fast timer busy.
func TestZeroWindowPersistProbe(t *testing.T) {
	var probes []uint32
	c := newTestConn(func(pkt []byte) {
		tcp := pkt[20:]
		if tcp[13] == 0x10 && len(pkt) == 40 {
			probes = append(probes, binary.BigEndian.Uint32(tcp[4:8]))
		}
	})
	c.sndWnd = 0
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = append(c.pending, make([]byte, 1000)...)
	c.flushPendingLocked()
	if c.sndNxt != c.sndUna {
		t.Fatal("data sent into a zero window")
	}
	if c.needsTimerLocked() {
		t.Fatal("zero-window wait keeps the fast timer busy")
	}
	now := time.Now()
	for i := 1; i <= 100; i++ {
		c.tickLocked(now.Add(time.Duration(i) * time.Second))
	}
	if len(probes) < 3 || len(probes) > 5 {
		t.Fatalf("%d probes in 100s, want one every %v", len(probes), usIdleTick)
	}
	for _, seq := range probes {
		if seq != c.sndUna-1 {
			t.Fatalf("probe seq %d, want sndUna-1 %d", seq, c.sndUna-1)
		}
	}
	// The window reopens: pending data flows and probing stops.
	c.handleSegLockedForTest(65535)
	if len(c.pending) != 0 || c.sndNxt == c.sndUna {
		t.Fatal("window update did not flush pending data")
	}
	if !c.probeAt.IsZero() {
		c.tickLocked(now.Add(200 * time.Second))
		if !c.probeAt.IsZero() {
			t.Fatal("probe timer survived the window update")
		}
	}
}

func (c *tcpConn) handleSegLockedForTest(wnd uint16) {
	c.mu.Unlock()
	c.handleSeg(c.rcvNxt, c.sndUna, 0x10, wnd, nil, nil)
	c.mu.Lock()
}

// Retransmit copies come from tun.BufPool and go back once acked or closed.
func TestRetransmitCopiesPooled(t *testing.T) {
	c := newTestConn(nil)
	data := make([]byte, 3*usDefaultMSS)
	if _, err := c.Write(data); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	if len(c.unacked) != 3 {
		c.mu.Unlock()
		t.Fatalf("%d segments in flight, want 3", len(c.unacked))
	}
	for _, s := range c.unacked {
		if s.box == nil || &(*s.box)[:1][0] != &s.data[0] {
			c.mu.Unlock()
			t.Fatal("segment data is not backed by its pooled buffer")
		}
	}
	// Partial ACK: the first segment is released, the second is trimmed but
	// keeps its buffer until fully acked.
	ack := c.sndUna + uint32(usDefaultMSS) + 100
	c.mu.Unlock()
	c.handleSeg(c.rcvNxt, ack, 0x10, 65535, nil, nil)
	c.mu.Lock()
	if len(c.unacked) != 2 || c.unacked[0].box == nil || len(c.unacked[0].data) != usDefaultMSS-100 {
		c.mu.Unlock()
		t.Fatalf("unexpected unacked after partial ACK: %d", len(c.unacked))
	}
	last := c.unacked[1].box
	c.forceCloseLocked()
	c.mu.Unlock()
	if c.unacked != nil || last == nil {
		t.Fatal("close kept unacked segments")
	}
}
