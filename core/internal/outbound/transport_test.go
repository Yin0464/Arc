package outbound

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"arc/core/internal/store"
	"arc/core/internal/store/storetest"
)

func TestClearEndpointSuppressesInflightStore(t *testing.T) {
	pendingClears.Wait()
	slot := epSlot(store.ProtoTrojan, 0)
	t.Cleanup(func() { slot.Store(nil) })
	ip := netip.MustParseAddr("203.0.113.10")
	gen := flowGen.Load()
	ClearEndpointCache()
	publishEP(slot, ip, gen)
	if slot.Load() != nil {
		t.Fatal("in-flight endpoint store survived clear")
	}
	publishEP(slot, ip, flowGen.Load())
	if slot.Load() == nil {
		t.Fatal("current-generation store dropped")
	}
}

func TestCloseLiveDropsTracked(t *testing.T) {
	storetest.Require(t)
	a, b := net.Pipe()
	defer b.Close()
	c := trackConn(a)
	CloseLiveConns()
	if _, err := c.Write([]byte{1}); err == nil {
		t.Fatal("tracked conn still writable")
	}
	if _, err := ResolveEndpoint(context.Background(), &store.Get().Regions[0], 255, store.ProtoTrojan); err == nil {
		t.Fatal("bad endpoint accepted")
	}
}
