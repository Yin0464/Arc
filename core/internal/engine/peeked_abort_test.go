package engine

import (
	"net"
	"testing"
	"time"
)

type abortSpy struct {
	net.Conn
	aborted, closed bool
}

func (a *abortSpy) Abort()       { a.aborted = true; _ = a.Conn.Close() }
func (a *abortSpy) Close() error { a.closed = true; return a.Conn.Close() }

// A sniffed 80/443 conn is wrapped in peekedConn, which hides Abort(),
// so HandleInboundTCP's failure path sends FIN (Close) instead of RST (Abort).
func TestSniffedConnKeepsAbort(t *testing.T) {
	app, peer := net.Pipe()
	defer peer.Close()
	spy := &abortSpy{Conn: app}
	go func() { _, _ = peer.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")) }()
	wrapped, host := sniffInitialPacket(spy, 80)
	if host != "example.com" {
		t.Fatalf("host = %q", host)
	}
	done := make(chan struct{})
	go func() { abortOrClose(wrapped); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("abortOrClose hung")
	}
	if !spy.aborted {
		t.Fatalf("sniffed conn was not aborted (closed=%v): peekedConn drops Abort()", spy.closed)
	}
}
