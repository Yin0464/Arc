package outbound

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
)

// gateConn blocks its Write until released and fails its Read on demand.
type gateConn struct {
	net.Conn
	wIn, wGo, rErr chan struct{}
}

func (g *gateConn) Write([]byte) (int, error) { close(g.wIn); <-g.wGo; return 0, errors.New("reset") }
func (g *gateConn) Read([]byte) (int, error)  { <-g.rErr; return 0, errors.New("reset") }
func (g *gateConn) Close() error              { return nil }
func (g *gateConn) LocalAddr() net.Addr       { return &net.TCPAddr{} }

type sinkConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *sinkConn) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}
func (s *sinkConn) Read([]byte) (int, error) { return 0, io.EOF }
func (s *sinkConn) Close() error             { return nil }
func (s *sinkConn) LocalAddr() net.Addr      { return &net.TCPAddr{} }

// A Read-side redial while a Write is still on the old connection replays
// that write; the failing Write must not send it a second time.
func TestHealConcurrentRedialNoDuplicate(t *testing.T) {
	old := &gateConn{wIn: make(chan struct{}), wGo: make(chan struct{}), rErr: make(chan struct{})}
	nc := &sinkConn{}
	h := &healConn{Conn: old, redial: func(context.Context) (net.Conn, error) { return nc, nil }}
	done := make(chan struct{})
	go func() { _, _ = h.Write([]byte("REQ")); close(done) }()
	<-old.wIn
	go func() { _, _ = h.Read(make([]byte, 8)) }()
	close(old.rErr)
	for {
		h.mu.Lock()
		swapped := h.Conn == net.Conn(nc)
		h.mu.Unlock()
		if swapped {
			break
		}
	}
	close(old.wGo)
	<-done
	nc.mu.Lock()
	got := nc.buf.String()
	nc.mu.Unlock()
	if got != "REQ" {
		t.Fatalf("redialed upstream got %q, want %q", got, "REQ")
	}
}
