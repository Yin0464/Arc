package outbound

import (
	"net"
	"testing"
)

type addrConn struct {
	net.Conn
	la net.Addr
}

func (c addrConn) LocalAddr() net.Addr { return c.la }

func TestEmptyStreamRetiresSession(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	sc := &sessConn{Conn: a}
	st, peer := net.Pipe()
	defer peer.Close()
	h := &healConn{Conn: addrConn{st, sc.LocalAddr()}, anytls: true}
	_ = h.Close()
	if _, err := sc.Write([]byte{1}); err == nil {
		t.Fatal("session conn still open after empty stream")
	}
}
