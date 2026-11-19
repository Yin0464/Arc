package anytls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestHeartbeatSkipsBufferedSession(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	var pad atomic.Pointer[PaddingFactory]
	s := NewClientSession(client, &pad, "t")
	s.sendPadding = false
	s.connLock.Lock()
	s.buffering = true
	s.connLock.Unlock()
	s.heartEvery = 20 * time.Millisecond
	go s.heartbeatLoop()
	time.Sleep(70 * time.Millisecond)
	if s.IsClosed() {
		t.Fatal("buffered session closed by heartbeat")
	}
	_ = server.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	buf := make([]byte, 8)
	if n, _ := server.Read(buf); n > 0 {
		t.Fatalf("wrote %d bytes while the handshake was still buffered", n)
	}
	s.connLock.Lock()
	s.buffering = false
	s.connLock.Unlock()
	_ = server.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := io.ReadFull(server, buf[:headerOverHeadSize]); err != nil {
		t.Fatal(err)
	}
	if buf[0] != cmdHeartRequest {
		t.Fatalf("cmd=%d", buf[0])
	}
	s.Close()
}

func TestUnknownFrameIsSkipped(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	var pad atomic.Pointer[PaddingFactory]
	s := NewClientSession(client, &pad, "t")
	s.heartMu.Lock()
	s.heartPending = true
	s.heartMisses = 1
	s.heartMu.Unlock()
	go func() { _ = s.recvLoop() }()
	var buf []byte
	buf = append(buf, 0x7f, 0, 0, 0, 0, 0, 4, 'A', 'B', 'C', 'D')
	buf = append(buf, cmdHeartResponse, 0, 0, 0, 0, 0, 0)
	if _, err := server.Write(buf); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.heartMu.Lock()
		pending := s.heartPending
		misses := s.heartMisses
		s.heartMu.Unlock()
		if !pending && misses == 0 {
			s.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("heart response was not applied; the frame stream desynced")
}

func TestStreamWriteSeesClose(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var pad atomic.Pointer[PaddingFactory]
	s := NewClientSession(a, &pad, "t")
	s.buffering = false
	_ = s.Close()
	st := newStream(1, s)
	if err := st.closeWithError(io.ErrClosedPipe); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	_, err := st.Write([]byte("x"))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write err=%v", err)
	}
}

func TestHeartbeatSparesBackPressuredSession(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	var pad atomic.Pointer[PaddingFactory]
	s := NewClientSession(client, &pad, "t")
	s.sendPadding = false
	s.heartEvery = 20 * time.Millisecond
	s.recvBusy.Store(true)
	go s.heartbeatLoop()
	time.Sleep(150 * time.Millisecond)
	if s.IsClosed() {
		t.Fatal("session closed while recvLoop was delivering to a stream")
	}
	s.recvBusy.Store(false)
	deadline := time.Now().Add(time.Second)
	for !s.IsClosed() {
		if time.Now().After(deadline) {
			t.Fatal("silent peer was not closed after missed heartbeats")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHeartbeatSparesRecentFrames(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	var pad atomic.Pointer[PaddingFactory]
	s := NewClientSession(client, &pad, "t")
	s.sendPadding = false
	s.heartEvery = 20 * time.Millisecond
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				s.lastRecv.Store(time.Now().UnixNano())
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()
	go s.heartbeatLoop()
	time.Sleep(150 * time.Millisecond)
	if s.IsClosed() {
		t.Fatal("session closed although frames kept arriving")
	}
	s.Close()
}

func TestDataWriteFailureClosesSession(t *testing.T) {
	client, server := net.Pipe()
	var pad atomic.Pointer[PaddingFactory]
	s := NewClientSession(client, &pad, "t")
	s.sendPadding = false
	_ = server.Close()
	if _, err := s.writeDataFrame(1, []byte("payload")); err == nil {
		t.Fatal("write to a closed peer succeeded")
	}
	if !s.IsClosed() {
		t.Fatal("broken session stayed open and could return to the idle pool")
	}
}

func TestClientCloseIdleKeepsOthers(t *testing.T) {
	var pad atomic.Pointer[PaddingFactory]
	c := &Client{}
	mk := func() (*Session, net.Conn) {
		a, b := net.Pipe()
		return NewClientSession(a, &pad, "t"), b
	}
	idle, p1 := mk()
	busy, p2 := mk()
	defer p1.Close()
	defer p2.Close()
	defer busy.Close()
	c.idleSessions = []*Session{idle}
	if n := c.CloseIdle(); n != 1 {
		t.Fatalf("closed %d idle sessions", n)
	}
	if !idle.IsClosed() || busy.IsClosed() {
		t.Fatal("CloseIdle touched a session outside the idle pool")
	}
}

// A payload above one frame's limit is split into consecutive PSH frames
// (cmd, sid, len) that carry the data in order, written in one conn write.
func TestLargeDataSplitIntoFrames(t *testing.T) {
	client, server := net.Pipe()
	var pad atomic.Pointer[PaddingFactory]
	s := NewClientSession(client, &pad, "t")
	s.sendPadding = false
	defer s.Close()
	data := make([]byte, 2*maxFrameDataLen+100)
	for i := range data {
		data[i] = byte(i * 31)
	}
	got := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(io.LimitReader(server, int64(len(data)+3*headerOverHeadSize)))
		got <- b
	}()
	if n, err := s.writeDataFrame(7, data); err != nil || n != len(data) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	b := <-got
	var out []byte
	for _, want := range []int{maxFrameDataLen, maxFrameDataLen, 100} {
		if len(b) < headerOverHeadSize || b[0] != cmdPSH || binary.BigEndian.Uint32(b[1:5]) != 7 ||
			int(binary.BigEndian.Uint16(b[5:7])) != want {
			t.Fatalf("bad frame header % x (want len %d)", b[:min(len(b), headerOverHeadSize)], want)
		}
		out = append(out, b[headerOverHeadSize:headerOverHeadSize+want]...)
		b = b[headerOverHeadSize+want:]
	}
	if len(b) != 0 || !bytes.Equal(out, data) {
		t.Fatal("reassembled payload differs")
	}
}

func TestAppendWasteLayout(t *testing.T) {
	b := appendWaste([]byte{0xAA, 0xBB}, 300)
	if len(b) != 2+headerOverHeadSize+300 || b[0] != 0xAA || b[1] != 0xBB || b[2] != cmdWaste ||
		binary.BigEndian.Uint32(b[3:7]) != 0 || binary.BigEndian.Uint16(b[7:9]) != 300 {
		t.Fatalf("bad waste frame % x", b[:9])
	}
	if bytes.Equal(b[9:], make([]byte, 300)) {
		t.Fatal("padding not randomized")
	}
}

// With the default padding scheme the padded first packets still decode to
// the exact PSH payloads, every other frame being a well-formed cmdWaste.
func TestPaddedWritesDecode(t *testing.T) {
	client, server := net.Pipe()
	var pad atomic.Pointer[PaddingFactory]
	UpdatePaddingScheme(DefaultPaddingScheme, &pad)
	s := NewClientSession(client, &pad, "t")
	got := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(server); got <- b }()
	var want []byte
	for i := 0; i < 12; i++ {
		p := bytes.Repeat([]byte{byte(i + 1)}, 50+i*97)
		if _, err := s.writeDataFrame(1, p); err != nil {
			t.Fatal(err)
		}
		want = append(want, p...)
	}
	_ = client.Close()
	b := <-got
	var data []byte
	wastes := 0
	for len(b) > 0 {
		if len(b) < headerOverHeadSize {
			t.Fatalf("truncated header % x", b)
		}
		cmd, sid, n := b[0], binary.BigEndian.Uint32(b[1:5]), int(binary.BigEndian.Uint16(b[5:7]))
		if len(b) < headerOverHeadSize+n {
			t.Fatalf("frame cmd=%d len=%d overruns %d bytes", cmd, n, len(b))
		}
		switch {
		case cmd == cmdPSH && sid == 1:
			data = append(data, b[headerOverHeadSize:headerOverHeadSize+n]...)
		case cmd == cmdWaste && sid == 0:
			wastes++
		default:
			t.Fatalf("unexpected frame cmd=%d sid=%d", cmd, sid)
		}
		b = b[headerOverHeadSize+n:]
	}
	if !bytes.Equal(data, want) || wastes == 0 {
		t.Fatalf("payload ok=%v wastes=%d", bytes.Equal(data, want), wastes)
	}
}
