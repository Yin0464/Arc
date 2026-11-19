package ustack

import (
	"net"
	"testing"
	"time"
)

// Hardening: a Write parked on a full send buffer must wake and return
// net.ErrClosed as soon as CloseWrite or Close queues the FIN, instead of
// waiting for the peer's next ACK or the retransmit give-up.
func TestCloseWriteWakesBlockedWrite(t *testing.T) {
	for _, useClose := range []bool{false, true} {
		st := &Stack{}
		st.closed.Store(true)
		c := &tcpConn{
			st:     st,
			state:  stEstablished,
			mss:    usDefaultMSS,
			sndUna: 100,
			sndNxt: 100 + usSndBuf, // send buffer full: room == 0
			rwait:  make(chan struct{}, 1),
			swait:  make(chan struct{}, 1),
		}
		errCh := make(chan error, 1)
		go func() {
			_, err := c.Write([]byte("blocked-write"))
			errCh <- err
		}()
		time.Sleep(20 * time.Millisecond)
		if useClose {
			_ = c.Close()
		} else {
			_ = c.CloseWrite()
		}
		select {
		case err := <-errCh:
			if err != net.ErrClosed {
				t.Fatalf("useClose=%v: Write err=%v, want net.ErrClosed", useClose, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("useClose=%v: Write remained blocked after close", useClose)
		}
	}
}
