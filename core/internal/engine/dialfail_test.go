package engine

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"arc/core/internal/dns"
)

type abortProbe struct {
	net.Conn
	aborted bool
	closed  bool
}

func (a *abortProbe) Abort() { a.aborted = true }

func (a *abortProbe) Close() error {
	a.closed = true
	if a.Conn != nil {
		return a.Conn.Close()
	}
	return nil
}

func TestAbortOrClosePrefersAbort(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	p := &abortProbe{Conn: a}
	abortOrClose(p)
	if !p.aborted {
		t.Fatal("Abort not called")
	}
	if p.closed {
		t.Fatal("Close should not be used when Abort exists")
	}
}

func TestAbortOrCloseFallsBackToClose(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	abortOrClose(a)
}

func TestShouldLateBindFakeIP(t *testing.T) {
	ip := dns.GlobalFakeIP.Allocate("late-bind.test", false)
	if !shouldLateBind(netip.AddrPortFrom(ip, 8443)) {
		t.Fatal("FakeIP non-sniff port should late-bind")
	}
	if shouldLateBind(netip.AddrPortFrom(ip, 443)) {
		t.Fatal("443 must not late-bind (sniff)")
	}
	if shouldLateBind(netip.AddrPortFrom(ip, 80)) {
		t.Fatal("80 must not late-bind")
	}
}

func TestHandleInboundTCPOrphanFakeAborts(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	p := &abortProbe{Conn: a}
	dst := netip.MustParseAddrPort("198.18.250.250:443")
	if _, ok := dns.GlobalFakeIP.Lookup(dst.Addr()); ok {
		t.Skip("slot allocated")
	}
	done := make(chan struct{})
	go func() {
		HandleInboundTCP(context.Background(), p, dst)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("hung")
	}
	if !p.aborted {
		t.Fatal("orphan fake must Abort")
	}
}
