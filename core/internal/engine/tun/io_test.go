package tun

import (
	"encoding/binary"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestWriter(qcap int, fn func(pkt []byte) error) *Writer {
	var mu sync.Mutex
	return NewWriter(nil, qcap, &mu, func(pkt []byte) { _ = fn(pkt) })
}

func TestTunWriterPreservesOrder(t *testing.T) {
	var mu sync.Mutex
	var got []uint32
	write := func(pkt []byte) error {
		mu.Lock()
		got = append(got, binary.BigEndian.Uint32(pkt))
		mu.Unlock()
		return nil
	}
	w := newTestWriter(8, write)
	const n = 2000
	for i := uint32(0); i < n; i++ {
		p := BufPool.Get().(*[]byte)
		b := (*p)[:4]
		binary.BigEndian.PutUint32(b, i)
		w.Enqueue(Packet{Pkt: b, Pooled: p})
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		l := len(got)
		mu.Unlock()
		if l == n || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	w.Shutdown()
	<-w.done
	if len(got) != n {
		t.Fatalf("got %d want %d", len(got), n)
	}
	for i, v := range got {
		if v != uint32(i) {
			t.Fatalf("order broken at %d: %d", i, v)
		}
	}
}

func TestTunWriterBackpressureBlocks(t *testing.T) {
	gate := make(chan struct{})
	var written atomic.Int32
	write := func([]byte) error { <-gate; written.Add(1); return nil }
	w := newTestWriter(4, write)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 64; i++ {
			w.Enqueue(Packet{Pkt: []byte{1}})
		}
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("producer did not block on full queue")
	default:
	}
	close(gate)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("producer stuck after drain")
	}
	w.Shutdown()
	<-w.done
}

func TestTunWriterShutdownUnblocksProducers(t *testing.T) {
	gate := make(chan struct{})
	write := func([]byte) error { <-gate; return nil }
	w := newTestWriter(1, write)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 16; i++ {
			w.Enqueue(Packet{Pkt: []byte{1}})
		}
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	w.Shutdown()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("producer stuck after shutdown")
	}
	close(gate)
	<-w.done
}

func TestTunReaderBatch(t *testing.T) {
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer wr.Close()
	for i := 0; i < 5; i++ {
		if _, err := wr.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	rd := NewReader(r, Batch)
	if !rd.batch {
		t.Skip("pipe not nonblocking")
	}
	n, err := rd.Read()
	if err != nil || n < 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	wr.Close()
	for {
		m, err := rd.Read()
		if err != nil {
			break
		}
		n += m
	}
	if n < 1 {
		t.Fatal("no packets")
	}
}
