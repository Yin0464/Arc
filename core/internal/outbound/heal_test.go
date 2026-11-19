package outbound

import (
	"testing"
	"time"
)

func TestHealBackoffNoStorm(t *testing.T) {
	lastHeal.Store(0)
	healGap.Store(0)
	emptyStreak.Store(0)
	heals := 0
	prev := lastHeal.Load()
	for i := 0; i < healEmptyStreak*100; i++ {
		noteEmptyStream()
		if l := lastHeal.Load(); l != prev {
			heals++
			prev = l
		}
	}
	if heals != 1 {
		t.Fatalf("heals=%d, want 1 within the gap", heals)
	}
	if g := time.Duration(healGap.Load()); g != 2*healMinGap {
		t.Fatalf("gap=%v after one failed heal", g)
	}

	for k := 0; k < 6; k++ {
		lastHeal.Store(time.Now().UnixNano() - healGap.Load() - 1)
		for i := 0; i < healEmptyStreak; i++ {
			noteEmptyStream()
		}
	}
	if g := time.Duration(healGap.Load()); g != healMaxGap {
		t.Fatalf("gap=%v, want cap %v", g, healMaxGap)
	}
	healGap.Store(0)
	lastHeal.Store(0)
	pendingClears.Wait()

	ClearEndpointCache()
}
