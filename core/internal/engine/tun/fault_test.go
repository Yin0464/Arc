package tun

import (
	"syscall"
	"testing"
	"time"
)

func TestTunFaultWindowTransientStreak(t *testing.T) {
	w := NewFaultWindow()
	w.limit = 50 * time.Millisecond
	w.minFaults = 3
	start := time.Unix(0, 0)
	if w.RecordFault(start) {
		t.Fatal("too early")
	}
	if w.RecordFault(start.Add(10 * time.Millisecond)) {
		t.Fatal("still early")
	}
	if !w.RecordFault(start.Add(60 * time.Millisecond)) {
		t.Fatal("expected tear-down after window+min faults")
	}
	w.RecordSuccess()
	if w.faults != 0 {
		t.Fatal("success did not reset")
	}
}

func TestTunFaultWindowGapResets(t *testing.T) {
	w := NewFaultWindow()
	w.limit = 30 * time.Millisecond
	w.minFaults = 2
	start := time.Unix(1, 0)
	_ = w.RecordFault(start)
	if w.RecordFault(start.Add(100 * time.Millisecond)) {
		t.Fatal("gap larger than limit should reset streak before counting")
	}
	if w.faults != 1 {
		t.Fatalf("faults=%d after gap restart", w.faults)
	}
}

func TestTunFaultKind(t *testing.T) {
	if FaultKind(syscall.EPIPE) != FaultPeerGone {
		t.Fatal("EPIPE should be peer-gone")
	}
	if FaultKind(syscall.ENOBUFS) != FaultTransient {
		t.Fatal("ENOBUFS should be transient")
	}
	if errno, ok := tunErrno(syscall.EAGAIN); !ok || errno != syscall.EAGAIN {
		t.Fatal("EAGAIN errno")
	}
	if FaultKind(syscall.EAGAIN) != FaultTransient {
		t.Fatal("EAGAIN should be transient")
	}
}
