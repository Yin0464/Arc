package anytls

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// synProbe checks, inside the SYN write itself, whether the stream is
// already registered.
type synProbe struct {
	net.Conn
	s    *Session
	seen chan bool
}

func (c *synProbe) Write(b []byte) (int, error) {
	if len(b) >= headerOverHeadSize && b[0] == cmdSYN {
		var hdr rawHeader
		copy(hdr[:], b)
		c.s.streamLock.RLock()
		_, ok := c.s.streams[hdr.StreamID()]
		c.s.streamLock.RUnlock()
		c.seen <- ok
	}
	return len(b), nil
}

// The stream must be registered before its SYN reaches the peer, so a fast
// reply on a reused session is never dropped as an unknown stream.
func TestOpenStreamRegistersBeforeSYN(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	var pad atomic.Pointer[PaddingFactory]
	UpdatePaddingScheme(DefaultPaddingScheme, &pad)
	probe := &synProbe{Conn: client, seen: make(chan bool, 1)}
	s := NewClientSession(probe, &pad, "t")
	probe.s = s
	s.sendPadding = false
	defer s.Close()
	if _, err := s.OpenStream(); err != nil {
		t.Fatal(err)
	}
	if !<-probe.seen {
		t.Fatal("stream not registered when the SYN reached the peer")
	}
}

func TestOpenStreamFailureUnregisters(t *testing.T) {
	client, server := net.Pipe()
	server.Close()
	var pad atomic.Pointer[PaddingFactory]
	UpdatePaddingScheme(DefaultPaddingScheme, &pad)
	s := NewClientSession(client, &pad, "t")
	s.sendPadding = false
	if _, err := s.OpenStream(); err == nil {
		t.Fatal("expected write failure")
	}
	s.streamLock.RLock()
	n := len(s.streams)
	s.streamLock.RUnlock()
	if n != 0 {
		t.Fatalf("%d streams left after failed SYN", n)
	}
}

// A stream closing while its session dies must never leave the closed
// session in the idle pool.
func TestStreamCloseDoesNotRepoolClosedSession(t *testing.T) {
	var pad atomic.Pointer[PaddingFactory]
	UpdatePaddingScheme(DefaultPaddingScheme, &pad)
	var mu sync.Mutex
	var sessions []net.Conn
	dial := func(ctx context.Context) (net.Conn, error) {
		c, srv := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, srv) }()
		mu.Lock()
		sessions = append(sessions, srv)
		mu.Unlock()
		return c, nil
	}
	c := NewClient(context.Background(), dial, &pad, "t", time.Minute, time.Minute, 0, false)
	defer c.Close()
	defer func() {
		mu.Lock()
		for _, s := range sessions {
			s.Close()
		}
		mu.Unlock()
	}()
	for i := 0; i < 200; i++ {
		st, err := c.CreateStream(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		sess := st.(*Stream).sess
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = st.Close() }()
		go func() { defer wg.Done(); _ = sess.Close() }()
		wg.Wait()
		c.idleMu.Lock()
		for _, s := range c.idleSessions {
			if s.IsClosed() {
				c.idleMu.Unlock()
				t.Fatalf("iteration %d: closed session re-pooled", i)
			}
		}
		c.idleMu.Unlock()
	}
}
