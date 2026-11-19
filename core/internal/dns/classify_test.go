package dns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"arc/core/internal/dnswire"
	"arc/core/internal/router"
)

func stubByType(t *testing.T, a, aaaa netip.Addr, aDelay, aaaaDelay time.Duration) {
	t.Helper()
	old := upstream.Load()
	var wg sync.WaitGroup
	var done atomic.Int32
	f := dohFunc(func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		defer done.Add(1)
		_, qt, qEnd, _ := dnswire.Question(q)
		ip, d := a, aDelay
		if qt == dnswire.TypeAAAA {
			ip, d = aaaa, aaaaDelay
		}
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if !ip.IsValid() {
			return dnswire.Answer(q, qEnd, 0, 0, 0, nil), nil
		}
		return dnswire.Answer(q, qEnd, 0, qt, 60, ip.AsSlice()), nil
	})
	upstream.Store(&dohBox{f})
	t.Cleanup(func() {
		time.Sleep(10 * time.Millisecond)
		wg.Wait()
		upstream.Store(old)
		ClearCache()
		router.ClearLearned()
	})
	ClearCache()
	router.ClearLearned()
}

func classifyTimed(t *testing.T, name string) (router.Action, time.Duration) {
	t0 := time.Now()
	act, _ := classify(context.Background(), name)
	return act, time.Since(t0)
}

func TestClassifyAAAAOnlyCN(t *testing.T) {
	stubByType(t, netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("240e:e9:6002::1"), 0, 10*time.Millisecond)
	if act, _ := classifyTimed(t, "v6cn.test"); act != router.ActionDirect {
		t.Fatalf("got %v", act)
	}
}

func TestClassifyCNAReturnsWithoutAAAA(t *testing.T) {
	stubByType(t, netip.MustParseAddr("114.114.114.114"), netip.Addr{}, 0, 400*time.Millisecond)
	act, d := classifyTimed(t, "v4cn.test")
	if act != router.ActionDirect || d > 50*time.Millisecond {
		t.Fatalf("got %v after %v", act, d)
	}
}

func TestClassifyAAAAWaitBounded(t *testing.T) {
	stubByType(t, netip.MustParseAddr("203.0.113.9"), netip.Addr{}, 0, 400*time.Millisecond)
	act, d := classifyTimed(t, "slow6.test")
	if act != router.ActionProxy || d > aaaaGrace+80*time.Millisecond {
		t.Fatalf("got %v after %v", act, d)
	}
}

func TestClassifyWaitsForA(t *testing.T) {
	stubByType(t, netip.MustParseAddr("114.114.114.114"), netip.Addr{}, 300*time.Millisecond, 0)
	if act, _ := classifyTimed(t, "slow4.test"); act != router.ActionDirect {
		t.Fatalf("got %v", act)
	}
}

// A NODATA A answer is no evidence, so a slower CN AAAA must still be heard
// instead of being cut off by the 100ms grace.
func TestClassifyNODATAADoesNotTruncateAAAA(t *testing.T) {
	stubByType(t, netip.Addr{}, netip.MustParseAddr("240e:e9:6002::1"), 0, aaaaGrace+150*time.Millisecond)
	if act, _ := classifyTimed(t, "v6only-cn.test"); act != router.ActionDirect {
		t.Fatalf("got %v", act)
	}
}

// The pre-check carries its own overall deadline, independent of the caller's.
func TestClassifyOwnDeadline(t *testing.T) {
	old := upstream.Load()
	t.Cleanup(func() { upstream.Store(old); ClearCache(); router.ClearLearned() })
	ClearCache()
	router.ClearLearned()
	var mu sync.Mutex
	var dls []time.Time
	upstream.Store(&dohBox{dohFunc(func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Error("pre-check query has no deadline")
		}
		mu.Lock()
		dls = append(dls, dl)
		mu.Unlock()
		_, qt, qEnd, _ := dnswire.Question(q)
		return dnswire.Answer(q, qEnd, 0, qt, 60, netip.MustParseAddr("203.0.113.9").AsSlice()), nil
	})})
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	t0 := time.Now()
	if act, err := classify(ctx, "deadline.test"); act != router.ActionProxy || err != nil {
		t.Fatalf("got %v %v", act, err)
	}
	t1 := time.Now()
	mu.Lock()
	defer mu.Unlock()
	if len(dls) == 0 {
		t.Fatal("no query")
	}
	for _, dl := range dls {
		if dl.Before(t0.Add(precheckTimeout)) || dl.After(t1.Add(precheckTimeout)) {
			t.Fatalf("deadline %v after start, want %v", dl.Sub(t0), precheckTimeout)
		}
	}
}

// A racer that never answers is cut at precheckTimeout even when the caller
// allows longer; the failure is not learned.
func TestClassifyTimeoutBounded(t *testing.T) {
	oldT := precheckTimeout
	precheckTimeout = 150 * time.Millisecond
	t.Cleanup(func() { precheckTimeout = oldT })
	old := upstream.Load()
	t.Cleanup(func() { upstream.Store(old); ClearCache(); router.ClearLearned() })
	ClearCache()
	router.ClearLearned()
	upstream.Store(&dohBox{dohFunc(func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})})
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	t0 := time.Now()
	act, err := classify(ctx, "hang.test")
	if d := time.Since(t0); act != router.ActionUnknown || err == nil || d > precheckTimeout+200*time.Millisecond {
		t.Fatalf("got %v %v after %v", act, err, d)
	}
	if router.MatchDomain("hang.test") != router.ActionUnknown {
		t.Fatal("failure was learned")
	}
}
