package dnswire

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
)

var errShortReply = errors.New("short dns reply")

// Exchange sends q to srv over plaintext UDP and retries over TCP when the
// reply is truncated. d supplies socket options (protect hook, timeouts).
func Exchange(ctx context.Context, d *net.Dialer, srv netip.AddrPort, q []byte) ([]byte, error) {
	if len(q) < 12 {
		return nil, errShortReply
	}
	resp, err := exchangeUDP(ctx, d, srv, q)
	if err != nil || resp[2]&0x02 == 0 {
		return resp, err
	}
	return exchangeTCP(ctx, d, srv, q)
}

func exchangeUDP(ctx context.Context, d *net.Dialer, srv netip.AddrPort, q []byte) ([]byte, error) {
	c, err := d.DialContext(ctx, "udp", srv.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err = c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 12 {
			return nil, errShortReply
		}
		if buf[0] == q[0] && buf[1] == q[1] {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func exchangeTCP(ctx context.Context, d *net.Dialer, srv netip.AddrPort, q []byte) ([]byte, error) {
	c, err := d.DialContext(ctx, "tcp", srv.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	msg := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(q)), uint16(len(q)))
	if _, err = c.Write(append(msg, q...)); err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err = io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err = io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	if len(resp) < 12 || resp[0] != q[0] || resp[1] != q[1] {
		return nil, errShortReply
	}
	return resp, nil
}
