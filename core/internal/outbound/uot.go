package outbound

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
)

const uotMagicV2 = "sp.v2.udp-over-tcp.arpa"

type uotConn struct {
	net.Conn
	mu      sync.Mutex
	reqSent bool
	dest    TargetAddr
}

func newUoTConn(c net.Conn, dest TargetAddr) *uotConn {
	return &uotConn{Conn: c, dest: dest}
}

func (c *uotConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dest := c.dest
	switch a := addr.(type) {
	case *PacketAddr:
		dest = a.TargetAddr
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			dest = TargetAddr{IP: ip.Unmap(), Port: uint16(a.Port)}
		}
	}
	pkt := make([]byte, 0, 22+len(dest.Domain)+len(p))
	pkt = appendUoTAddr(pkt, dest)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(len(p)))
	pkt = append(pkt, p...)

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.Conn.Write(c.prependReq(pkt)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// prependReq puts the one-time request header (0 + c.dest) in front of pkt
// on the first write; callers hold c.mu.
func (c *uotConn) prependReq(pkt []byte) []byte {
	if c.reqSent {
		return pkt
	}
	c.reqSent = true
	return append(appendUoTAddr(make([]byte, 1, 20+len(c.dest.Domain)+len(pkt)), c.dest), pkt...)
}

func (c *uotConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	if req := c.prependReq(nil); req != nil {
		if _, err := c.Conn.Write(req); err != nil {
			c.mu.Unlock()
			return 0, nil, err
		}
	}
	c.mu.Unlock()

	dest, err := readUoTAddr(c.Conn)
	if err != nil {
		return 0, nil, err
	}
	var ln [2]byte
	if _, err = io.ReadFull(c.Conn, ln[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(ln[:]))
	if n > len(p) {
		return 0, nil, io.ErrShortBuffer
	}
	if _, err = io.ReadFull(c.Conn, p[:n]); err != nil {
		return 0, nil, err
	}
	return n, &PacketAddr{dest}, nil
}

func appendUoTAddr(b []byte, t TargetAddr) []byte {
	switch {
	case t.Domain != "":
		b = append(append(b, 2, byte(len(t.Domain))), t.Domain...)
	case t.IP.Is4():
		a := t.IP.As4()
		b = append(append(b, 0), a[:]...)
	default:
		a := t.IP.As16()
		b = append(append(b, 1), a[:]...)
	}
	return append(b, byte(t.Port>>8), byte(t.Port))
}

func readUoTAddr(r io.Reader) (TargetAddr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return TargetAddr{}, err
	}
	var t TargetAddr
	switch atyp[0] {
	case 0:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return TargetAddr{}, err
		}
		t.IP = netip.AddrFrom4(a)
	case 1:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return TargetAddr{}, err
		}
		t.IP = netip.AddrFrom16(a)
	case 2:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return TargetAddr{}, err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return TargetAddr{}, err
		}
		t.Domain = string(b)
	default:
		return TargetAddr{}, errors.New("bad uot atyp")
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return TargetAddr{}, err
	}
	t.Port = binary.BigEndian.Uint16(pb[:])
	return t, nil
}
