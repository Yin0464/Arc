package outbound

import (
	"context"
	"net"
	"sync"

	"arc/core/internal/outbound/trojan"
	"arc/core/internal/store"
)

func dialNodeTLS(ctx context.Context, region *store.Region, node *store.Node, defALPN []string) (net.Conn, error) {
	gen := flowGen.Load()
	rawConn, err := dialRawTCP(ctx, region, node)
	if err != nil {
		return nil, err
	}
	tConn, err := nodeTLS(ctx, rawConn, region.NodeSNI(node), region.NodeOpts(node), defALPN)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	c := trackConn(tConn)
	if flowGen.Load() != gen {
		_ = c.Close()
		return nil, net.ErrClosed
	}
	return c, nil
}

// dialTrojan opens a Trojan session: TCP, TLS, then the Trojan header.
func dialTrojan(ctx context.Context, region *store.Region, node *store.Node, cmd trojan.Command, target TargetAddr) (net.Conn, error) {
	gen := flowGen.Load()
	raw, err := dialRawTCP(ctx, region, node)
	if err != nil {
		return nil, err
	}
	c, err := wrapTrojan(ctx, raw, region.NodeSNI(node), region.NodeOpts(node), store.Get().Profile(node.Proto), cmd, target)
	if err != nil {
		return nil, err
	}
	c = trackConn(c)
	if flowGen.Load() != gen {
		_ = c.Close()
		return nil, net.ErrClosed
	}
	return c, nil
}

// wrapTrojan continues after TCP: TLS, then the Trojan header on the first write.
func wrapTrojan(ctx context.Context, raw net.Conn, sni string, o *store.NodeOpts, prof *store.UpstreamProfile, cmd trojan.Command, target TargetAddr) (net.Conn, error) {
	if o == nil {
		o = &store.NodeOpts{}
	}
	c, err := trojanTransport(ctx, raw, sni, o)
	if err != nil {
		return nil, err
	}
	var key [trojan.KeyLength]byte
	if prof != nil {
		copy(key[:], prof.Key)
	}
	return &trojanLazy{Conn: c, key: key, cmd: cmd, addr: appendAddr(nil, target)}, nil
}

func trojanTransport(ctx context.Context, raw net.Conn, sni string, o *store.NodeOpts) (net.Conn, error) {
	c, err := nodeTLS(ctx, raw, sni, o, trojan.DefaultALPN)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}

type trojanLazy struct {
	net.Conn
	once sync.Once
	err  error
	key  [trojan.KeyLength]byte
	cmd  trojan.Command
	addr []byte
}

func (c *trojanLazy) header(p []byte) (bool, error) {
	sent := false
	c.once.Do(func() {
		sent = true
		// Header and first payload go out in one buffer and one write.
		buf := trojan.AppendHeader(make([]byte, 0, trojan.KeyLength+5+len(c.addr)+len(p)), c.key, c.cmd, c.addr)
		_, c.err = c.Conn.Write(append(buf, p...))
	})
	return sent, c.err
}

func (c *trojanLazy) Write(p []byte) (int, error) {
	if sent, err := c.header(p); sent || err != nil {
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *trojanLazy) Read(p []byte) (int, error) {
	if _, err := c.header(nil); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}
