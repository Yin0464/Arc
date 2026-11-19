package anytls

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWastePaddingIsRandomFill(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var got []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		deadline := time.Now().Add(2 * time.Second)
		_ = server.SetReadDeadline(deadline)
		for {
			n, err := server.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if err != nil {
				return
			}
			if len(got) > 50 {
				return
			}
		}
	}()

	var pad atomic.Pointer[PaddingFactory]

	UpdatePaddingScheme([]byte("stop=3\n0=8-8\n1=40-40\n2=40-40\n"), &pad)
	s := NewClientSession(client, &pad, "test")
	s.sendPadding = true
	s.buffering = false
	s.pktCounter.Store(0)

	small := []byte("hi")
	if _, err := s.writeConn(small); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	wg.Wait()

	found := false
	for i := 0; i+7 < len(got); i++ {
		if got[i] != cmdWaste {
			continue
		}
		ln := int(binary.BigEndian.Uint16(got[i+5 : i+7]))
		if ln <= 0 || i+7+ln > len(got) {
			continue
		}
		body := got[i+7 : i+7+ln]
		if bytes.Equal(body, make([]byte, ln)) {
			t.Fatalf("waste padding all-zero len=%d", ln)
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("no waste frame in %d bytes: %x", len(got), got)
	}
}

func TestRandomFillNotZeros(t *testing.T) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(b, make([]byte, 32)) {
		t.Fatal("rand.Read returned zeros")
	}
}

func TestWarmPoolMinIdle(t *testing.T) {
	var dials atomic.Int32
	dialOut := func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		a, b := net.Pipe()
		go func() {
			defer b.Close()

			_, _ = io.Copy(io.Discard, b)
		}()
		return a, nil
	}
	var pad atomic.Pointer[PaddingFactory]
	UpdatePaddingScheme(DefaultPaddingScheme, &pad)
	c := NewClient(context.Background(), dialOut, &pad, "t", 30*time.Second, 60*time.Second, 2, false)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c.Warm(ctx, 2)
	if c.idleCount() < 1 {
		t.Fatalf("warm idle=%d dials=%d", c.idleCount(), dials.Load())
	}
	if c.MinIdleSession() != 2 {
		t.Fatalf("minIdle=%d", c.MinIdleSession())
	}
}

func TestCreateStreamRetriesAfterDeadIdle(t *testing.T) {
	var dials atomic.Int32
	dialOut := func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			_, _ = io.Copy(io.Discard, b)
		}()
		return a, nil
	}
	var pad atomic.Pointer[PaddingFactory]
	UpdatePaddingScheme(DefaultPaddingScheme, &pad)
	c := NewClient(context.Background(), dialOut, &pad, "t", 30*time.Second, 60*time.Second, 1, false)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	deadA, deadB := net.Pipe()
	_ = deadB.Close()
	_ = deadA.Close()
	dead := NewClientSession(deadA, &pad, "dead")
	_ = dead.Close()
	c.idleMu.Lock()
	c.idleSessions = append(c.idleSessions, dead)
	c.idleMu.Unlock()

	st, err := c.CreateStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if dials.Load() < 1 {
		t.Fatal("expected dial after skipping dead idle")
	}
}
