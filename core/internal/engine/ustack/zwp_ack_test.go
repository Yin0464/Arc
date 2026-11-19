package ustack

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// A zero-window probe hitting a full receive buffer must be ACKed at once
// with the current rcvNxt and a zero window, or the peer's probe timer
// never learns that the window is still closed.
func TestZeroWindowProbeIsAcked(t *testing.T) {
	var sent [][]byte
	st := &Stack{cfg: Config{Send: func(pkt []byte, _ *[]byte) {
		sent = append(sent, append([]byte(nil), pkt...))
	}}}
	c := &tcpConn{
		fam:      0,
		localAP:  netip.MustParseAddrPort("10.0.0.1:443"),
		remoteAP: netip.MustParseAddrPort("10.0.0.2:50000"),
		mss:      usDefaultMSS,
		rwait:    make(chan struct{}, 1),
		swait:    make(chan struct{}, 1),
		st:       st,
		state:    stEstablished,
		lastRx:   time.Now(),
		rto:      time.Hour,
		rcvNxt:   1000,
		sndNxt:   5000,
		rbuf:     make([]byte, usRcvBuf),
	}
	c.rcvWnd = 0
	c.consumePayloadLocked(c.rcvNxt, 0x10, []byte{0x42})
	if len(sent) != 1 {
		t.Fatalf("sent %d packets, want one immediate ACK", len(sent))
	}
	tcp := sent[0][20:]
	if tcp[13] != 0x10 {
		t.Fatalf("flags=%#x", tcp[13])
	}
	if ack := binary.BigEndian.Uint32(tcp[8:12]); ack != 1000 {
		t.Fatalf("ack=%d want 1000", ack)
	}
	if wnd := binary.BigEndian.Uint16(tcp[14:16]); wnd != 0 {
		t.Fatalf("window=%d want 0", wnd)
	}
	if c.delayedAck {
		t.Fatal("probe ACK was delayed")
	}
}
