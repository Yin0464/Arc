package dns

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"arc/core/internal/dnswire"
	"arc/core/internal/router"
)

func TestResolveAnswersBurstOfSlowQueries(t *testing.T) {
	old := upstream.Load()
	release := make(chan struct{})
	f := dohFunc(func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		<-release
		_, qt, qEnd, _ := dnswire.Question(q)
		return dnswire.Answer(q, qEnd, 0, qt, 60, netip.MustParseAddr("223.5.5.5").AsSlice()), nil
	})
	upstream.Store(&dohBox{f})
	t.Cleanup(func() { upstream.Store(old); ClearCache(); router.ClearLearned() })
	ClearCache()

	const n = 200
	var replies atomic.Int32
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("burst-%d.test", i)
		router.LearnDomain(name, router.ActionDirect)
		Resolve(context.Background(), dnswire.Query(name, dnswire.TypeA), func([]byte) { replies.Add(1) })
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for replies.Load() < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := replies.Load(); got != n {
		t.Fatalf("answered %d of %d concurrent slow queries", got, n)
	}
}

func TestAnswerHonorsOuterDeadline(t *testing.T) {
	const name = "slow-deadline.test"
	old := upstream.Load()
	f := dohFunc(func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	upstream.Store(&dohBox{f})
	t.Cleanup(func() { upstream.Store(old); ClearCache(); router.ClearLearned() })
	ClearCache()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	_ = Answer(ctx, dnswire.Query(name, dnswire.TypeA))
	if time.Since(start) > 2*time.Second {
		t.Fatal("Answer ignored deadline")
	}
}

func TestFakeIPInvalidateClearsLookup(t *testing.T) {
	ip := GlobalFakeIP.Allocate("invalidate-me.test", false)
	if _, ok := GlobalFakeIP.Lookup(ip); !ok {
		t.Fatal("allocate failed")
	}
	GlobalFakeIP.Invalidate()
	if _, ok := GlobalFakeIP.Lookup(ip); ok {
		t.Fatal("lookup survived Invalidate")
	}
}

func TestOnNetworkChangedClearsDipsAndFakeIP(t *testing.T) {
	ip := GlobalFakeIP.Allocate("net-change.test", false)
	dip := netip.MustParseAddr("203.0.113.77")
	router.NoteDirectIP(dip, time.Minute)
	if !router.IsDirectIP(dip) {
		t.Fatal("NoteDirectIP failed")
	}
	OnNetworkChanged()
	if router.IsDirectIP(dip) {
		t.Fatal("dips survived OnNetworkChanged")
	}
	if _, ok := GlobalFakeIP.Lookup(ip); ok {
		t.Fatal("FakeIP survived OnNetworkChanged")
	}
}

func TestClassifyFailReturnsFakeIP(t *testing.T) {
	const name = "classify-fail-soft.test"
	t.Cleanup(func() { ClearCache(); router.ClearLearned() })
	old := upstream.Load()
	f := dohFunc(func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		return nil, context.DeadlineExceeded
	})
	upstream.Store(&dohBox{f})
	t.Cleanup(func() { upstream.Store(old) })
	ClearCache()
	resp := Answer(context.Background(), dnswire.Query(name, dnswire.TypeA))
	if !isFake(t, resp) {
		t.Fatalf("classify failure should FakeIP, got %x", resp)
	}
}
