package outbound

import (
	"context"
	"errors"
	"net"
	"time"

	"arc/core/internal/outbound/trojan"
	"arc/core/internal/store"
)

func DialNodeTCP(ctx context.Context, region *store.Region, node *store.Node, target TargetAddr) (net.Conn, error) {
	return dialNodeTCP(ctx, region, node, target, false)
}

func DialNodeProbe(ctx context.Context, region *store.Region, node *store.Node, target TargetAddr) (net.Conn, error) {
	return dialNodeTCP(ctx, region, node, target, true)
}

func dialNodeTCP(ctx context.Context, region *store.Region, node *store.Node, target TargetAddr, probe bool) (net.Conn, error) {
	dial := func(ctx context.Context) (net.Conn, error) {
		if node.Proto == store.ProtoAnyTLS {
			return anytlsStream(ctx, region, node, appendAddr(nil, target))
		}
		return dialTrojan(ctx, region, node, trojan.CommandTCP, target)
	}
	c, err := dial(ctx)
	if err != nil {
		return nil, err
	}

	r := &healConn{Conn: c, probe: probe, redial: dial}
	if node.Proto == store.ProtoAnyTLS {
		r.anytls = true
	}
	return r, nil
}

var errNoNodes = errors.New("no node table loaded")

func DialTCP(ctx context.Context, target TargetAddr) (net.Conn, error) {
	region, node := GetActiveNode()
	if node == nil {
		return nil, errNoNodes
	}
	return DialNodeTCP(ctx, region, node, target)
}

func DialUDP(ctx context.Context, target TargetAddr) (net.PacketConn, error) {
	region, node := GetActiveNode()
	if node == nil {
		return nil, errNoNodes
	}
	return DialNodeUDP(ctx, region, node, target)
}

func ActiveSupportsUDP() bool {
	a, n := GetActiveNode()
	return n != nil && a.NodeOpts(n).UDP
}

func DialNodeUDP(ctx context.Context, region *store.Region, node *store.Node, target TargetAddr) (net.PacketConn, error) {
	if !region.NodeOpts(node).UDP {
		return nil, errors.New("udp unsupported")
	}
	if node.Proto == store.ProtoAnyTLS {
		c, err := anytlsStream(ctx, region, node, appendSocksDomain(nil, uotMagicV2, 0))
		if err != nil {
			return nil, err
		}
		return newUoTConn(c, target), nil
	}
	c, err := dialTrojan(ctx, region, node, trojan.CommandUDP, target)
	if err != nil {
		return nil, err
	}
	return trojan.NewPacketConn(c), nil
}

func Prewarm() {
	region, node := GetActiveNode()
	if region == nil || node == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if node.Proto == store.ProtoAnyTLS {
			c := anytlsFor(region, node)
			c.sc.Warm(ctx, c.sc.MinIdleSession())
			return
		}
		raw, err := dialRawTCP(ctx, region, node)
		if err != nil {
			return
		}
		c, err := trojanTransport(ctx, raw, region.NodeSNI(node), region.NodeOpts(node))
		if err != nil {
			return
		}
		_ = c.Close()
	}()
}

func closeProtoClients() { ClearAnyTLSPool() }

func appendAddr(b []byte, t TargetAddr) []byte {
	if b == nil {
		b = make([]byte, 0, 20+len(t.Domain))
	}
	switch {
	case t.Domain != "":
		return appendSocksDomain(b, t.Domain, t.Port)
	case t.IP.Is4():
		a := t.IP.As4()
		b = append(append(b, 1), a[:]...)
	default:
		a := t.IP.As16()
		b = append(append(b, 4), a[:]...)
	}
	return append(b, byte(t.Port>>8), byte(t.Port))
}

func appendSocksDomain(b []byte, domain string, port uint16) []byte {
	b = append(append(b, 3, byte(len(domain))), domain...)
	return append(b, byte(port>>8), byte(port))
}
