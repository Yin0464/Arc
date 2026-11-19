package anytls

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func synFrame(cmd byte, sid byte) []byte {
	f := []byte{cmd, 0, 0, 0, sid, 0, 0}
	if cmd == cmdPSH {
		f[6] = 1
		f = append(f, 'x')
	}
	return f
}

func synTestSession(t *testing.T, newest uint32) (*Session, net.Conn, *atomic.Bool) {
	t.Helper()
	client, server := net.Pipe()
	var pad atomic.Pointer[PaddingFactory]
	UpdatePaddingScheme(DefaultPaddingScheme, &pad)
	s := NewClientSession(client, &pad, "t")
	s.streamID.Store(newest)
	var cancelled atomic.Bool
	s.synDone = func() { cancelled.Store(true) }
	go func() { _ = s.recvLoop() }()
	t.Cleanup(func() { s.Close(); server.Close() })
	return s, server, &cancelled
}

// A PSH, FIN or SYNACK for the newest stream proves the peer took its SYN,
// so the 3s watchdog is cancelled and does not kill the session.
func TestStreamFrameCancelsSynWatchdog(t *testing.T) {
	for _, cmd := range []byte{cmdPSH, cmdFIN, cmdSYNACK} {
		_, server, cancelled := synTestSession(t, 2)
		if _, err := server.Write(synFrame(cmd, 2)); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(time.Second)
		for !cancelled.Load() && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
		}
		if !cancelled.Load() {
			t.Fatalf("cmd %d did not cancel the SYN watchdog", cmd)
		}
	}
}

// A late frame of an older stream must leave the newest stream's watchdog
// running.
func TestStaleFrameKeepsSynWatchdog(t *testing.T) {
	for _, cmd := range []byte{cmdPSH, cmdFIN, cmdSYNACK} {
		s, server, cancelled := synTestSession(t, 3)
		s.heartMu.Lock()
		s.heartPending = true
		s.heartMu.Unlock()
		buf := append(synFrame(cmd, 2), cmdHeartResponse, 0, 0, 0, 0, 0, 0)
		if _, err := server.Write(buf); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			s.heartMu.Lock()
			done := !s.heartPending
			s.heartMu.Unlock()
			if done {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		s.heartMu.Lock()
		pending := s.heartPending
		s.heartMu.Unlock()
		if pending {
			t.Fatalf("cmd %d: sentinel frame not processed", cmd)
		}
		if cancelled.Load() {
			t.Fatalf("stale cmd %d cancelled the newest SYN watchdog", cmd)
		}
	}
}
