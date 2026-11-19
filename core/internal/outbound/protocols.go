package outbound

import (
	"context"
	"net"
	"net/netip"
	"time"

	"arc/core/internal/protect"
	"arc/core/internal/store"
)

func dialRawTCP(ctx context.Context, region *store.Region, node *store.Node) (net.Conn, error) {
	if epSlot(node.Proto, node.EpID).Load() == nil {
		if ip, ok := diskEP(region, node.EpID, node.Proto); ok {
			go func() {
				rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_, _ = ResolveEndpoint(rctx, region, node.EpID, node.Proto)
			}()

			return raceStaleDial(ctx, region, node.EpID, node.Port, ip, node.Proto, protect.Dialer().DialContext)
		}
	}
	ip, err := ResolveEndpoint(ctx, region, node.EpID, node.Proto)
	if err != nil {
		return nil, err
	}
	return protect.Dialer().DialContext(ctx, "tcp", netip.AddrPortFrom(ip, node.Port).String())
}

type PacketAddr struct{ TargetAddr }

func (a *PacketAddr) Network() string { return "udp" }
func (a *PacketAddr) String() string {
	if a == nil {
		return ""
	}
	return a.TargetAddr.String()
}
