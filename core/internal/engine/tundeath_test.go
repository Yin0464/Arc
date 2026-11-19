package engine

import (
	"testing"
	"time"
)

func TestUnexpectedTunDeathStopsAndCallbacks(t *testing.T) {
	s := &CustomStack{}
	s.running.Store(true)
	s.epoch.Store(7)
	called := make(chan struct{}, 1)
	prev := onUnexpectedStop.Load()
	SetOnUnexpectedStop(func() { called <- struct{}{} })
	defer onUnexpectedStop.Store(prev)

	s.handleUnexpectedTunDeath(7)
	if s.IsRunning() {
		t.Fatal("still running after unexpected TUN death")
	}
	if s.epoch.Load() == 7 {
		t.Fatal("epoch not bumped")
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("OnUnexpectedStop not called")
	}

	s.running.Store(true)
	s.epoch.Store(9)
	s.handleUnexpectedTunDeath(8)
	if !s.IsRunning() || s.epoch.Load() != 9 {
		t.Fatal("stale epoch should not stop a newer generation")
	}
}
