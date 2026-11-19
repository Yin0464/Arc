package dnswire

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestExchangeTruncatedFallsBackToTCP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skip("tcp port busy:", err)
	}
	defer ln.Close()
	go func() {
		b := make([]byte, 512)
		n, a, err := pc.ReadFrom(b)
		if err != nil {
			return
		}
		_, _, qEnd, _ := Question(b[:n])
		r := Answer(b[:n], qEnd, 0, 0, 0, nil)
		r[2] |= 0x02
		pc.WriteTo(r, a)
	}()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var h [2]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(h[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		_, qt, qEnd, _ := Question(q)
		r := Answer(q, qEnd, 0, qt, 60, []byte{10, 1, 2, 3})
		c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	resp, err := Exchange(ctx, &net.Dialer{}, srv, Query("tc.test", TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if ip, _ := FirstIP(resp); ip != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("got %v", ip)
	}
}
