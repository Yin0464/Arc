package engine

import (
	"arc/core/internal/engine/tun"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestWriteOutUnlocksBeforeTransientSleep(t *testing.T) {
	s := &CustomStack{}
	s.epoch.Store(1)
	fw := tun.NewFaultWindow()
	var unlocked atomic.Bool
	var slept atomic.Bool
	var calls atomic.Int32
	oldSleep := tunWriteSleep
	oldWrite := writeTUNPacketFn
	defer func() {
		tunWriteSleep = oldSleep
		writeTUNPacketFn = oldWrite
	}()
	writeTUNPacketFn = func(tun *os.File, pkt []byte) error {
		n := calls.Add(1)
		if n == 1 {
			return syscall.ENOBUFS
		}
		return nil
	}
	tunWriteSleep = func(d time.Duration) {
		slept.Store(true)
		if s.wmu.TryLock() {
			unlocked.Store(true)
			s.wmu.Unlock()
		}
		if d != tun.TransientBackoff {
			t.Errorf("backoff=%v want %v", d, tun.TransientBackoff)
		}
	}

	s.wmu.Lock()
	s.writeOut(nil, []byte{1, 2, 3}, 1, &fw)
	s.wmu.Unlock()

	if !slept.Load() {
		t.Fatal("expected transient sleep path")
	}
	if !unlocked.Load() {
		t.Fatal("wmu still held during sleep")
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d want retry", calls.Load())
	}
}

func TestWriteOutStaleEpochDoesNotKill(t *testing.T) {
	s := &CustomStack{}
	s.running.Store(true)
	s.epoch.Store(5)
	fw := tun.NewFaultWindow()
	died := make(chan struct{})
	SetOnUnexpectedStop(func() { close(died) })
	t.Cleanup(func() { SetOnUnexpectedStop(nil) })
	old := writeTUNPacketFn
	writeTUNPacketFn = func(*os.File, []byte) error { return syscall.EPIPE }
	t.Cleanup(func() { writeTUNPacketFn = old })

	s.wmu.Lock()
	s.writeOut(nil, []byte{1}, 4, &fw)
	s.wmu.Unlock()
	select {
	case <-died:
		t.Fatal("stale write killed the live generation")
	case <-time.After(50 * time.Millisecond):
	}
	if !s.running.Load() || s.epoch.Load() != 5 {
		t.Fatalf("running=%v epoch=%d", s.running.Load(), s.epoch.Load())
	}

	s.wmu.Lock()
	s.writeOut(nil, []byte{1}, 5, &fw)
	s.wmu.Unlock()
	select {
	case <-died:
	case <-time.After(time.Second):
		t.Fatal("current generation write did not report tun death")
	}
}
