package outbound

import (
	"net"
	"testing"
	"time"
)

func TestHealClosesOnlyStalledConns(t *testing.T) {
	stalled := &stallConn{closed: make(chan struct{})}
	busy := &stallConn{closed: make(chan struct{})}
	sc := TrackConn(stalled).(*liveConn)
	bc := TrackConn(busy).(*liveConn)
	t.Cleanup(func() { _ = sc.Close(); _ = bc.Close() })
	sc.last.Store(time.Now().Add(-healStaleAfter - time.Second).UnixNano())

	healStalled(false)

	select {
	case <-stalled.closed:
	case <-time.After(time.Second):
		t.Fatal("stalled connection survived self-heal")
	}
	select {
	case <-busy.closed:
		t.Fatal("connection that received data recently was closed by self-heal")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestLiveConnReadRefreshesActivity(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	lc := TrackConn(a).(*liveConn)
	defer lc.Close()
	old := time.Now().Add(-time.Minute).UnixNano()
	lc.last.Store(old)
	go func() { _, _ = b.Write([]byte{1}) }()
	if _, err := lc.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if lc.last.Load() <= old {
		t.Fatal("read did not refresh the activity time")
	}
}
