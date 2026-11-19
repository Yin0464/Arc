package outbound

import (
	"io"
	"net"
	"testing"
	"time"
)

type stallConn struct {
	net.Conn
	closed chan struct{}
}

func (c *stallConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}
func (c *stallConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *stallConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *stallConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *stallConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *stallConn) SetDeadline(time.Time) error      { return nil }
func (c *stallConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stallConn) SetWriteDeadline(time.Time) error { return nil }

func TestTrackConnClosedOnNetworkChange(t *testing.T) {
	c := &stallConn{closed: make(chan struct{})}
	_ = TrackConn(c)
	ClearEndpointCache()
	select {
	case <-c.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("tracked conn not closed by ClearEndpointCache")
	}
}

type cwConn struct {
	stallConn
	cw int
}

func (c *cwConn) CloseWrite() error { c.cw++; return nil }

func TestLiveConnForwardsCloseWrite(t *testing.T) {
	inner := &cwConn{stallConn: stallConn{closed: make(chan struct{})}}
	c := TrackConn(inner)
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("liveConn missing CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if inner.cw != 1 {
		t.Fatal("CloseWrite not forwarded")
	}
}
