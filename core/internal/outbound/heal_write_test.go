package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type shortWriter struct {
	net.Conn
	mu     sync.Mutex
	n      int
	err    error
	wrote  []byte
	closed bool
}

func (s *shortWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := min(s.n, len(p))
	s.wrote = append(s.wrote, p[:n]...)
	return n, s.err
}

func (s *shortWriter) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}
func (s *shortWriter) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (s *shortWriter) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (s *shortWriter) SetDeadline(t time.Time) error      { return nil }
func (s *shortWriter) SetReadDeadline(t time.Time) error  { return nil }
func (s *shortWriter) SetWriteDeadline(t time.Time) error { return nil }
func (s *shortWriter) Read(p []byte) (int, error)         { return 0, io.EOF }

type captureConn struct {
	net.Conn
	mu    sync.Mutex
	wrote []byte
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.wrote = append(c.wrote, p...)
	c.mu.Unlock()
	return len(p), nil
}
func (c *captureConn) Read(p []byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(t time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(t time.Time) error { return nil }

func TestHealConnPartialWriteDoesNotDuplicate(t *testing.T) {
	old := &shortWriter{n: 3, err: errors.New("broken pipe")}
	healed := &captureConn{}
	h := &healConn{
		Conn: old,
		redial: func(ctx context.Context) (net.Conn, error) {
			return healed, nil
		},
	}
	payload := []byte("HELLO-WORLD")
	n, err := h.Write(payload)
	if err != nil {
		t.Fatalf("Write after heal: n=%d err=%v", n, err)
	}
	if n != len(payload) {
		t.Fatalf("want full write %d, got %d", len(payload), n)
	}
	healed.mu.Lock()
	got := append([]byte(nil), healed.wrote...)
	healed.mu.Unlock()
	if string(got) != string(payload) {
		t.Fatalf("replay=%q want %q", got, payload)
	}
}

func TestHealConnShortWriteNoErrNoDuplicateInSent(t *testing.T) {
	sw := &shortWriter{n: 4, err: nil}
	h := &healConn{Conn: sw, redial: func(context.Context) (net.Conn, error) {
		return nil, errors.New("unused")
	}}
	p := []byte("abcdefgh")
	n, err := h.Write(p)
	if err != nil || n != 4 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	h.mu.Lock()
	sent := append([]byte(nil), h.sent...)
	h.mu.Unlock()
	if string(sent) != "abcd" {
		t.Fatalf("sent=%q want abcd (trimmed to delivered)", sent)
	}
	n2, err2 := h.Write(p[4:])
	if err2 != nil || n2 != 4 {
		t.Fatalf("second write n=%d err=%v", n2, err2)
	}
	h.mu.Lock()
	sent = append([]byte(nil), h.sent...)
	h.mu.Unlock()
	if string(sent) != "abcdefgh" {
		t.Fatalf("sent after remainder=%q", sent)
	}
}
