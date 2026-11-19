package anytls

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// loopConn replays one frame left times, then reports EOF.
type loopConn struct {
	net.Conn
	frame     []byte
	off, left int
}

func (c *loopConn) Read(p []byte) (int, error) {
	if c.left == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.frame[c.off:])
	if c.off += n; c.off == len(c.frame) {
		c.off, c.left = 0, c.left-1
	}
	return n, nil
}
func (c *loopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *loopConn) Close() error                     { return nil }
func (c *loopConn) SetDeadline(time.Time) error      { return nil }
func (c *loopConn) SetWriteDeadline(time.Time) error { return nil }

func pshFrame(sid uint32, payload []byte) []byte {
	f := make([]byte, headerOverHeadSize, headerOverHeadSize+len(payload))
	f[0] = cmdPSH
	binary.BigEndian.PutUint32(f[1:5], sid)
	binary.BigEndian.PutUint16(f[5:7], uint16(len(payload)))
	return append(f, payload...)
}

// The reused receive buffer must never leak bytes of one frame into the next.
func TestRecvLoopBufferReuse(t *testing.T) {
	var wire []byte
	var want []byte
	for i, n := range []int{5000, 100, 65535, 7} {
		p := bytes.Repeat([]byte{byte('a' + i)}, n)
		wire = append(wire, pshFrame(1, p)...)
		want = append(want, p...)
	}
	c := &loopConn{frame: wire, left: 1}
	s := &Session{conn: c, die: make(chan struct{}), streams: map[uint32]*Stream{}}
	st := newStream(1, s)
	s.streams[1] = st
	go s.recvLoop()
	got, _ := io.ReadAll(st)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, want %d (or content differs)", len(got), len(want))
	}
}

func BenchmarkRecvLoop(b *testing.B) {
	c := &loopConn{frame: pshFrame(1, make([]byte, 16<<10)), left: b.N}
	s := &Session{conn: c, die: make(chan struct{}), streams: map[uint32]*Stream{}}
	st := newStream(1, s)
	s.streams[1] = st
	go func() { _, _ = io.Copy(io.Discard, st) }()
	b.SetBytes(16 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	_ = s.recvLoop()
}
