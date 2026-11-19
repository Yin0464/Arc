package outbound

import (
	"net"
	"testing"
	"time"
)

func TestProbeStreamsDoNotFeedHeal(t *testing.T) {
	lastHeal.Store(0)
	healGap.Store(0)
	emptyStreak.Store(0)
	t.Cleanup(func() { emptyStreak.Store(0); healGap.Store(0); lastHeal.Store(0) })

	live := &stallConn{closed: make(chan struct{})}
	_ = TrackConn(live)
	for i := 0; i < 32; i++ {
		a, b := net.Pipe()
		h := &healConn{Conn: a, probe: true}
		_ = h.Close()
		_ = b.Close()
	}
	if n := emptyStreak.Load(); n != 0 {
		t.Fatalf("probe closes fed the heal streak: %d", n)
	}
	if lastHeal.Load() != 0 {
		t.Fatal("probe closes triggered a heal")
	}
	select {
	case <-live.closed:
		t.Fatal("live connection dropped by probe-triggered heal")
	case <-time.After(50 * time.Millisecond):
	}

	emptyStreak.Store(3)
	pa, pb := net.Pipe()
	h := &healConn{Conn: pa, probe: true}
	go func() { _, _ = pb.Write([]byte{1}); _ = pb.Close() }()
	if _, err := h.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
	if n := emptyStreak.Load(); n != 3 {
		t.Fatalf("probe success reset streak to %d", n)
	}

	ra, rb := net.Pipe()
	_ = (&healConn{Conn: ra}).Close()
	_ = rb.Close()
	if n := emptyStreak.Load(); n != 4 {
		t.Fatalf("real empty stream not counted: %d", n)
	}
	_ = live.Close()
	pendingClears.Wait()
}
