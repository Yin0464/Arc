package engine

import (
	"arc/core/internal/engine/tun"
	"io"
	"net"
	"testing"
)

func TestCsumAddMatchesStraight(t *testing.T) {
	straight := func(sum uint32, b []byte) uint32 {
		for len(b) >= 2 {
			sum += uint32(b[0])<<8 | uint32(b[1])
			b = b[2:]
		}
		if len(b) == 1 {
			sum += uint32(b[0]) << 8
		}
		return sum
	}
	for n := 0; n <= 2000; n++ {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*3 + n)
		}
		if got, want := tun.CsumAdd(uint32(n), b), straight(uint32(n), b); got != want {
			t.Fatalf("len %d got %x want %x", n, got, want)
		}
	}
}

func BenchmarkCsum1400(b *testing.B) {
	buf := make([]byte, 1400)
	for i := range buf {
		buf[i] = byte(i)
	}
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	for b.Loop() {
		_ = tun.CsumFold(tun.CsumAdd(0, buf))
	}
}

func BenchmarkPipeStreams(b *testing.B) {
	const n = 256 << 10
	payload := make([]byte, n)
	b.SetBytes(n)
	b.ReportAllocs()
	for b.Loop() {
		leftC, leftS := benchPair(b)
		rightC, rightS := benchPair(b)
		errc := make(chan error, 2)
		if tc, ok := rightS.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		go func() {
			pipeStreams(leftS, rightC)
			errc <- nil
		}()
		go func() {
			_, err := io.Copy(io.Discard, rightS)
			errc <- err
		}()
		if _, err := leftC.Write(payload); err != nil {
			b.Fatal(err)
		}
		_ = leftC.Close()
		<-errc
		<-errc
		_ = rightS.Close()
		_ = leftS.Close()
		_ = rightC.Close()
	}
}

func benchPair(b *testing.B) (net.Conn, net.Conn) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	done := make(chan net.Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		done <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	select {
	case s := <-done:
		return c, s
	case err := <-errc:
		c.Close()
		b.Fatal(err)
		return nil, nil
	}
}
