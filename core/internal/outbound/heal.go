package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type healConn struct {
	net.Conn
	mu     sync.Mutex
	redial func(context.Context) (net.Conn, error)
	anytls bool
	probe  bool
	sent   []byte
	got    atomic.Bool
	used   bool
	closed atomic.Bool
}

func (h *healConn) cur() net.Conn { h.mu.Lock(); defer h.mu.Unlock(); return h.Conn }

func (h *healConn) retry(old net.Conn, err error) bool {
	if h.anytls && !h.got.Load() {
		retireSession(old)
	}
	if h.redial == nil || h.got.Load() || err == io.EOF || errors.Is(err, os.ErrDeadlineExceeded) || h.closed.Load() {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.Conn != old {
		return true
	}
	if h.used {
		return false
	}
	h.used = true
	retireSession(old)
	_ = old.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, e := h.redial(ctx)
	if e != nil {
		return false
	}
	if len(h.sent) > 0 {
		if _, e = c.Write(h.sent); e != nil {
			_ = c.Close()
			return false
		}
	}
	h.Conn, h.sent = c, nil
	return true
}

func (h *healConn) Read(p []byte) (int, error) {
	for {
		c := h.cur()
		n, err := c.Read(p)
		if n > 0 {
			if !h.got.Swap(true) {
				if !h.probe {
					emptyStreak.Store(0)
					healGap.Store(0)
				}
				h.mu.Lock()
				h.sent, h.used = nil, true
				h.mu.Unlock()
			}
			return n, err
		}
		if err == nil || !h.retry(c, err) {
			return n, err
		}
	}
}

func (h *healConn) Write(p []byte) (int, error) {
	h.mu.Lock()
	c := h.Conn
	base := len(h.sent)
	track := h.redial != nil && !h.used && base+len(p) <= 64<<10
	if track {
		h.sent = append(h.sent, p...)
	} else if !h.got.Load() {
		h.used, h.sent = true, nil
		track = false
	}
	h.mu.Unlock()
	n, err := c.Write(p)
	n = max(n, 0)
	replayed := false
	if track && n < len(p) {
		h.mu.Lock()
		// A redial since the append already replayed all of p.
		if replayed = h.Conn != c; !replayed && base+n <= len(h.sent) {
			h.sent = h.sent[:base+n]
		}
		h.mu.Unlock()
	}
	if err != nil && h.retry(c, err) {
		if n < len(p) && !replayed {
			m, e2 := h.cur().Write(p[n:])
			if e2 != nil {
				return n + m, e2
			}
		}
		return len(p), nil
	}
	return n, err
}

func (h *healConn) CloseWrite() error {
	if cw, ok := h.cur().(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (h *healConn) Close() error {
	c := h.cur()
	if !h.closed.Swap(true) && !h.got.Load() {
		if h.anytls {
			retireSession(c)
		}
		if !h.probe {
			noteEmptyStream()
		}
	}
	return c.Close()
}

func (h *healConn) SetDeadline(t time.Time) error      { return h.cur().SetDeadline(t) }
func (h *healConn) SetReadDeadline(t time.Time) error  { return h.cur().SetReadDeadline(t) }
func (h *healConn) SetWriteDeadline(t time.Time) error { return h.cur().SetWriteDeadline(t) }

var (
	emptyStreak   atomic.Int32
	lastHeal      atomic.Int64
	healGap       atomic.Int64
	pendingClears sync.WaitGroup
)

const (
	healEmptyStreak = 5
	healMinGap      = 10 * time.Second
	healMaxGap      = 40 * time.Second
)

func noteEmptyStream() {
	if emptyStreak.Add(1) < healEmptyStreak {
		return
	}
	now := time.Now().UnixNano()
	gap := healGap.Load()
	if gap == 0 {
		gap = int64(healMinGap)
	}
	if last := lastHeal.Load(); now-last < gap || !lastHeal.CompareAndSwap(last, now) {
		return
	}
	escalate := gap > int64(healMinGap)
	healGap.Store(min(gap*2, int64(healMaxGap)))
	emptyStreak.Store(0)
	pendingClears.Add(1)
	go func() {
		defer pendingClears.Done()
		healStalled(escalate)
	}()
}

// healStaleAfter is how long a tracked connection may go without receiving
// data before self-heal treats it as stalled.
const healStaleAfter = 10 * time.Second

// healStalled is the self-heal action. It re-resolves endpoints (the active
// one first, every one on escalation), drops idle AnyTLS sessions, and closes
// only connections that received nothing for healStaleAfter, so streams that
// are still moving data survive. Network changes use InvalidateActive /
// ClearEndpointCache instead.
func healStalled(escalate bool) {
	_, node := GetActiveNode()
	if escalate {
		for p := range epCache {
			for i := range epCache[p] {
				epCache[p][i].Store(nil)
			}
		}
		dohIPCache.Clear()
		closeIdleAnyTLS(nil)
	} else if node != nil {
		epSlot(node.Proto, node.EpID).Store(nil)
		closeIdleAnyTLS(node)
	}
	closeStale(healStaleAfter)
	directDoH.CloseIdleConnections()
}
