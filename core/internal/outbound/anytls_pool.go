package outbound

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"arc/core/internal/outbound/anytls"
	"arc/core/internal/store"
)

const (
	anytlsMinIdle     = 2
	anytlsIdleCheck   = 30 * time.Second
	anytlsIdleTimeout = 60 * time.Second
)

type anytlsClient struct {
	sc  *anytls.Client
	pad atomic.Pointer[anytls.PaddingFactory]
}

var (
	anytlsMu      sync.Mutex
	anytlsClients = map[*store.Node]*anytlsClient{}
)

func anytlsPoolParams(o *store.NodeOpts) (pad []byte, meta string, idleCheck, idleTimeout time.Duration, minIdle int) {
	pad = anytls.DefaultPaddingScheme
	idleCheck, idleTimeout, minIdle = anytlsIdleCheck, anytlsIdleTimeout, anytlsMinIdle
	if o == nil {
		return pad, "", idleCheck, idleTimeout, minIdle
	}
	if o.PaddingScheme != "" {
		pad = []byte(o.PaddingScheme)
	}
	meta = o.ClientMetadata
	if o.IdleSessionCheckIntervalSec != 0 {
		idleCheck = time.Duration(o.IdleSessionCheckIntervalSec) * time.Second
	}
	if o.IdleSessionTimeoutSec != 0 {
		idleTimeout = time.Duration(o.IdleSessionTimeoutSec) * time.Second
	}
	if o.MinIdleSessionSet {
		minIdle = o.MinIdleSession
	}
	return pad, meta, idleCheck, idleTimeout, minIdle
}

func anytlsFor(region *store.Region, node *store.Node) *anytlsClient {
	anytlsMu.Lock()
	defer anytlsMu.Unlock()
	if c := anytlsClients[node]; c != nil {
		return c
	}
	c := &anytlsClient{}
	o := region.NodeOpts(node)
	pad, meta, idleCheck, idleTimeout, minIdle := anytlsPoolParams(o)
	if !anytls.UpdatePaddingScheme(pad, &c.pad) {
		anytls.UpdatePaddingScheme(anytls.DefaultPaddingScheme, &c.pad)
	}
	pw := store.Get().Profile(node.Proto).Key
	dialOut := func(ctx context.Context) (net.Conn, error) {
		tc, err := dialNodeTLS(ctx, region, node, nil)
		if err != nil {
			return nil, err
		}
		var paddingLen int
		if pad := c.pad.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
			paddingLen = pad[0]
		}
		buf := make([]byte, 32+2+paddingLen)
		copy(buf, pw)
		binary.BigEndian.PutUint16(buf[32:34], uint16(paddingLen))
		if paddingLen > 0 {
			_, _ = rand.Read(buf[34:])
		}
		if _, err = tc.Write(buf); err != nil {
			tc.Close()
			return nil, err
		}
		return &sessConn{Conn: tc}, nil
	}
	c.sc = anytls.NewClient(context.Background(), dialOut, &c.pad, meta, idleCheck, idleTimeout, minIdle, false)
	anytlsClients[node] = c
	return c
}

type sessConn struct{ net.Conn }

type sessAddr struct {
	net.Addr
	c *sessConn
}

func (c *sessConn) LocalAddr() net.Addr { return &sessAddr{c.Conn.LocalAddr(), c} }

// touchSession marks the session's tracked TLS connection as live when a
// pooled session is reused, so healing does not treat it as stalled before
// the new stream's first reply arrives.
func touchSession(st net.Conn) {
	if a, ok := st.LocalAddr().(*sessAddr); ok {
		if lc, ok := a.c.Conn.(*liveConn); ok {
			lc.last.Store(time.Now().UnixNano())
		}
	}
}

func retireSession(st net.Conn) {
	if a, ok := st.LocalAddr().(*sessAddr); ok {
		_ = a.c.Close()
	}
}

func ClearAnyTLSPool() {
	anytlsMu.Lock()
	old := anytlsClients
	anytlsClients = map[*store.Node]*anytlsClient{}
	anytlsMu.Unlock()
	for _, c := range old {
		_ = c.sc.Close()
	}
}

func clearAnyTLSNode(node *store.Node) {
	if node == nil {
		return
	}
	anytlsMu.Lock()
	c := anytlsClients[node]
	delete(anytlsClients, node)
	anytlsMu.Unlock()
	if c != nil {
		_ = c.sc.Close()
	}
}

// closeIdleAnyTLS closes pooled AnyTLS sessions without an open stream, for
// node only, or for every node when node is nil.
func closeIdleAnyTLS(node *store.Node) {
	anytlsMu.Lock()
	var cs []*anytlsClient
	for n, c := range anytlsClients {
		if node == nil || n == node {
			cs = append(cs, c)
		}
	}
	anytlsMu.Unlock()
	for _, c := range cs {
		c.sc.CloseIdle()
	}
}

func anytlsStream(ctx context.Context, region *store.Region, node *store.Node, dst []byte) (net.Conn, error) {
	st, err := anytlsFor(region, node).sc.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	touchSession(st)
	if _, err = st.Write(dst); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}
