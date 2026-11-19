package engine

import (
	"io"
	"net"
	"testing"
	"time"
)

// After the app side finishes, a remote that never sends FIN must not keep
// the relay (two goroutines + two 64 KiB buffers) alive forever.
func TestPipeStreamsHalfCloseIdleBound(t *testing.T) {
	old := halfCloseIdle
	halfCloseIdle = 50 * time.Millisecond
	t.Cleanup(func() { halfCloseIdle = old })
	app, c1 := net.Pipe()
	c2, remote := net.Pipe()
	defer remote.Close()
	go func() { _, _ = io.Copy(io.Discard, remote) }()
	done := make(chan struct{})
	go func() { pipeStreams(c1, c2); close(done) }()
	_, _ = app.Write([]byte("req"))
	_ = app.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay still open after half-close idle bound")
	}
}

// A half-closed relay whose other direction keeps moving data stays open
// past the bound: the deadline is an idle timeout, not a total one.
func TestPipeStreamsHalfCloseKeepsActiveFlow(t *testing.T) {
	old := halfCloseIdle
	halfCloseIdle = 80 * time.Millisecond
	t.Cleanup(func() { halfCloseIdle = old })
	app, c1 := tcpPair(t)
	c2, remote := tcpPair(t)
	go pipeStreams(c1, c2)
	if _, err := app.Write([]byte("req")); err != nil {
		t.Fatal(err)
	}
	_ = app.(*net.TCPConn).CloseWrite()
	go func() {
		buf := make([]byte, 3)
		_, _ = io.ReadFull(remote, buf)
		for i := 0; i < 8; i++ {
			time.Sleep(40 * time.Millisecond)
			if _, err := remote.Write([]byte("x")); err != nil {
				return
			}
		}
		_ = remote.(*net.TCPConn).CloseWrite()
	}()
	_ = app.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, _ := io.ReadAll(app)
	if len(got) != 8 {
		t.Fatalf("app got %d bytes over a 320ms stream, want 8 (relay cut while active?)", len(got))
	}
}
