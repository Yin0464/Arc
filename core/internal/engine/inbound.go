package engine

import (
	"arc/core/internal/dns"
	"arc/core/internal/dnswire"
	"arc/core/internal/engine/sniff"
	"arc/core/internal/outbound"
	"arc/core/internal/protect"
	"arc/core/internal/router"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

func abortOrClose(c net.Conn) {
	if a, ok := c.(interface{ Abort() }); ok {
		a.Abort()
		return
	}
	_ = c.Close()
}

func HandleInboundTCP(ctx context.Context, c net.Conn, dst netip.AddrPort) {
	ip, port := dst.Addr(), dst.Port()
	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	ok := false
	defer func() {
		cancel()
		if !ok {
			abortOrClose(c)
		}
	}()
	relay := func(r net.Conn, err error) bool {
		if err != nil {
			return false
		}
		cancel()
		pipeStreams(c, r)
		return true
	}
	proxy := func(t outbound.TargetAddr) bool { return relay(outbound.DialTCP(dialCtx, t)) }

	if domain, found, orphan := dns.LookupDest(ip); found {
		if router.IsDirectOrLAN(router.MatchDomain(domain)) {
			ok = relay(dialDirectName(dialCtx, domain, port))
			return
		}
		ok = proxy(outbound.TargetAddr{Domain: domain, Port: port})
		return
	} else if orphan {
		return
	}
	ipAct := router.ResolveIPAction(ip)
	if ipAct == router.ActionLAN {
		ok = relay(dialDirect(dialCtx, dst, 0))
		return
	}
	var host string
	if port == 443 || port == 80 {
		c, host = sniffInitialPacket(c, port)
		if host != "" {
			switch router.MatchDomain(host) {
			case router.ActionProxy:
				ok = proxy(outbound.TargetAddr{Domain: host, Port: port})
				return
			case router.ActionDirect:
				if cnNameDirect(host, ip) {
					ok = relay(dialDirectFallback(dialCtx, dst, host))
					return
				}
			}
		}
	}
	if ipAct == router.ActionDirect {
		ok = relay(dialDirectFallback(dialCtx, dst, host))
		return
	}
	ok = proxy(outbound.TargetAddr{Domain: host, IP: ip, Port: port})
}

func cnNameDirect(host string, ip netip.Addr) bool {
	return router.IsCNDomain(host) && !router.IsGoogleIP(ip)
}

var lookupDirect = dns.LookupDirect

const directNameHEDelay = 250 * time.Millisecond

func dialDirectName(ctx context.Context, host string, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 2)
	tryFamily := func(qt uint16, delay time.Duration) {
		if delay > 0 {
			t := time.NewTimer(delay)
			defer t.Stop()
			select {
			case <-ctx.Done():
				ch <- res{nil, ctx.Err()}
				return
			case <-t.C:
			}
		}
		var last error = errNoAddr
		for i, a := range lookupDirect(ctx, host, qt) {
			if i == 3 || ctx.Err() != nil {
				break
			}
			c, e := dialDirect(ctx, netip.AddrPortFrom(a, port), 4*time.Second)
			if e == nil {
				ch <- res{c, nil}
				return
			}
			last = e
		}
		ch <- res{nil, last}
	}
	go tryFamily(dnswire.TypeA, 0)
	go tryFamily(dnswire.TypeAAAA, directNameHEDelay)
	var last error = errNoAddr
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil && r.c != nil {
			cancel()
			if i == 0 {
				go func() {
					if rr := <-ch; rr.c != nil {
						_ = rr.c.Close()
					}
				}()
			}
			return r.c, nil
		}
		if r.err != nil {
			last = r.err
		}
	}
	return nil, last
}

var errNoAddr = errors.New("direct name has no usable address")

func dialDirectFallback(ctx context.Context, dst netip.AddrPort, host string) (net.Conn, error) {
	v6 := dst.Addr().Is6() && !dst.Addr().Is4In6()
	// A dead IPv6 path is bounded at 4s so the IPv4 fallback still runs
	// before the app gives up.
	var first time.Duration
	if v6 {
		first = 4 * time.Second
	}
	c, err := dialDirect(ctx, dst, first)
	if err == nil || !v6 || ctx.Err() != nil {
		return c, err
	}
	if host == "" {
		host = dns.NameForV6(dst.Addr())
	}
	if host == "" {
		return nil, err
	}
	for i, a := range lookupDirect(ctx, host, dnswire.TypeA) {
		if i == 3 || ctx.Err() != nil {
			break
		}
		if c, e := dialDirect(ctx, netip.AddrPortFrom(a, dst.Port()), 4*time.Second); e == nil {
			return c, nil
		}
	}
	return nil, err
}

func dialDirect(ctx context.Context, dst netip.AddrPort, timeout time.Duration) (net.Conn, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	c, err := protect.Dialer().DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, err
	}
	return outbound.TrackConn(c), nil
}

var copyPool = sync.Pool{New: func() any {
	b := make([]byte, 64<<10)
	return &b
}}

// halfCloseIdle bounds a relay after one side finished: the other direction
// must keep moving data or it is closed, so a peer that never sends FIN can
// not pin the goroutines and buffers forever.
var halfCloseIdle = 2 * time.Minute

// idleAfterHalfClose refreshes a read deadline before every read once armed.
type idleAfterHalfClose struct {
	net.Conn
	armed atomic.Bool
}

func (r *idleAfterHalfClose) Read(p []byte) (int, error) {
	if r.armed.Load() {
		_ = r.Conn.SetReadDeadline(time.Now().Add(halfCloseIdle))
	}
	return r.Conn.Read(p)
}

func pipeStreams(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	r1, r2 := &idleAfterHalfClose{Conn: c1}, &idleAfterHalfClose{Conn: c2}
	cp := func(dst net.Conn, src, other *idleAfterHalfClose) {
		defer wg.Done()
		bp := copyPool.Get().(*[]byte)
		defer copyPool.Put(bp)
		_, _ = io.CopyBuffer(dst, src, *bp)
		closeWrite(dst)
		other.armed.Store(true)
		_ = dst.SetReadDeadline(time.Now().Add(halfCloseIdle))
	}
	go cp(c1, r2, r1)
	go cp(c2, r1, r2)
	wg.Wait()
	_ = c1.Close()
	_ = c2.Close()
}

type closeWriter interface{ CloseWrite() error }

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

type peekedConn struct {
	net.Conn
	buf []byte
}

func (c *peekedConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		if len(c.buf) == 0 {
			c.buf = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *peekedConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

var sniffPool = sync.Pool{New: func() any {
	b := make([]byte, 4096)
	return &b
}}

func sniffInitialPacket(conn net.Conn, port uint16) (net.Conn, string) {
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	bufp := sniffPool.Get().(*[]byte)
	b := *bufp
	n := 0
	for n < len(b) {
		m, err := conn.Read(b[n:])
		n += m
		if (port == 443 && sniff.TLSRecordReady(b[:n])) || (port != 443 && bytes.Contains(b[:n], []byte("\r\n\r\n"))) {
			break
		}
		if err != nil || m == 0 {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	if n <= 0 {
		sniffPool.Put(bufp)
		return conn, ""
	}
	raw := make([]byte, n)
	copy(raw, b[:n])
	sniffPool.Put(bufp)
	wrapped := &peekedConn{Conn: conn, buf: raw}
	if port == 443 {
		return wrapped, router.CleanLowerDomain(sniff.TLSSNI(raw))
	}
	return wrapped, router.CleanLowerDomain(sniff.HTTPHost(raw))
}

func shouldLateBind(local netip.AddrPort) bool {
	p := local.Port()
	if p == 80 || p == 443 || p == 53 || p == 853 {
		return false
	}
	_, found, orphan := dns.LookupDest(local.Addr())
	return found || orphan
}

func dialForLateBind(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	ip, port := dst.Addr(), dst.Port()
	if domain, found, orphan := dns.LookupDest(ip); found {
		if router.IsDirectOrLAN(router.MatchDomain(domain)) {
			return dialDirectName(ctx, domain, port)
		}
		return outbound.DialTCP(ctx, outbound.TargetAddr{Domain: domain, Port: port})
	} else if orphan {
		return nil, errOrphanFake
	}
	ipAct := router.ResolveIPAction(ip)
	switch ipAct {
	case router.ActionLAN, router.ActionDirect:
		return dialDirect(ctx, dst, 0)
	default:
		return outbound.DialTCP(ctx, outbound.TargetAddr{IP: ip, Port: port})
	}
}

var errOrphanFake = errors.New("orphan fake-ip")

func handleTCPConn(c net.Conn, dst netip.AddrPort, upstream net.Conn) {
	if dst.Port() == 53 {
		handleTCPDNSConn(c)
		return
	}
	if upstream != nil {
		pipeStreams(c, upstream)
		return
	}
	HandleInboundTCP(context.Background(), c, dst)
}

// handleTCPDNSConn serves DNS over TCP. A client may pipeline several queries
// on one connection; each one gets a fresh idle deadline.
func handleTCPDNSConn(conn net.Conn) {
	defer conn.Close()
	var lenHdr [2]byte
	for {
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := io.ReadFull(conn, lenHdr[:]); err != nil {
			return
		}
		qLen := int(binary.BigEndian.Uint16(lenHdr[:]))
		if qLen == 0 || qLen > 2048 {
			return
		}
		q := make([]byte, qLen)
		if _, err := io.ReadFull(conn, q); err != nil {
			return
		}
		resp := dns.Answer(context.Background(), q)
		if len(resp) == 0 {
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(4 * time.Second))
		if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...)); err != nil {
			return
		}
	}
}

func (c *peekedConn) Abort() { abortOrClose(c.Conn) }
