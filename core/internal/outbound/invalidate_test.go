package outbound

import (
	"net/netip"
	"testing"
	"time"

	"arc/core/internal/store"
)

func clearAllEP() {
	for p := range epCache {
		for i := range epCache[p] {
			epCache[p][i].Store(nil)
		}
	}
}

func TestInvalidateActiveScoped(t *testing.T) {
	t.Cleanup(func() { clearAllEP(); ClearEndpointCache() })

	SwitchActive(0, 0)
	_, node := GetActiveNode()
	if node == nil {
		t.Fatal("no active node")
	}
	ip0 := netip.MustParseAddr("203.0.113.10")
	ip1 := netip.MustParseAddr("203.0.113.11")
	other := store.ProtoAnyTLS
	if node.Proto == other {
		other = store.ProtoTrojan
	}
	epSlot(node.Proto, node.EpID).Store(&ip0)
	epSlot(other, node.EpID).Store(&ip1)
	otherEP := node.EpID ^ 1
	epSlot(node.Proto, otherEP).Store(&ip1)

	InvalidateActive()
	if epSlot(node.Proto, node.EpID).Load() != nil {
		t.Fatal("active ep not cleared")
	}
	if epSlot(other, node.EpID).Load() == nil || epSlot(node.Proto, otherEP).Load() == nil {
		t.Fatal("other ep cleared by scoped invalidate")
	}
}

func TestHealFirstScopedThenFull(t *testing.T) {
	lastHeal.Store(0)
	healGap.Store(0)
	emptyStreak.Store(0)
	ip0 := netip.MustParseAddr("203.0.113.20")
	ip1 := netip.MustParseAddr("203.0.113.21")
	for p := range epCache {
		epCache[p][0].Store(&ip0)
		epCache[p][1].Store(&ip1)
	}
	t.Cleanup(func() {
		emptyStreak.Store(0)
		healGap.Store(0)
		lastHeal.Store(0)
		clearAllEP()
		ClearEndpointCache()
	})

	for i := 0; i < healEmptyStreak; i++ {
		noteEmptyStream()
	}
	pendingClears.Wait()
	cached := 0
	for p := range epCache {
		for i := range 2 {
			if epCache[p][i].Load() != nil {
				cached++
			}
		}
	}
	if cached == 0 {
		t.Fatal("first heal cleared all endpoints")
	}

	lastHeal.Store(time.Now().UnixNano() - healGap.Load() - 1)
	for i := 0; i < healEmptyStreak; i++ {
		noteEmptyStream()
	}
	pendingClears.Wait()
	for p := range epCache {
		for i := range epCache[p] {
			if epCache[p][i].Load() != nil {
				t.Fatalf("ep %d/%d still cached after escalate", p, i)
			}
		}
	}
}
