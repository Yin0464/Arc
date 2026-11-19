package dns

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"arc/core/internal/dnswire"
)

func withUpstream(t *testing.T, f dohFunc) {
	old := upstream.Load()
	upstream.Store(&dohBox{f})
	t.Cleanup(func() { upstream.Store(old); ClearCache() })
	ClearCache()
}

func expire(k cacheKey, by time.Duration) {
	cacheMu.Lock()
	e := dnsCache[k]
	e.expires, e.stale = e.expires.Add(-by), e.stale.Add(-by)
	dnsCache[k] = e
	cacheMu.Unlock()
}

func TestServeStaleRefreshesInBackground(t *testing.T) {
	var calls atomic.Int32
	withUpstream(t, func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		n := calls.Add(1)
		_, qt, qEnd, _ := dnswire.Question(q)
		return dnswire.Answer(q, qEnd, 0, qt, 5, []byte{1, 2, 3, byte(n)}), nil
	})
	const name = "stale.example"
	q := dnswire.Query(name, dnswire.TypeA)
	if _, err := cachedDoH(context.Background(), name, dnswire.TypeA, q); err != nil {
		t.Fatal(err)
	}
	k := cacheKey{name, dnswire.TypeA, false}
	cacheMu.Lock()
	ttl := time.Until(dnsCache[k].expires)
	cacheMu.Unlock()
	if ttl < 59*time.Second || ttl > 61*time.Second {
		t.Fatalf("TTL floor not applied: %v", ttl)
	}
	expire(k, 61*time.Second)
	t0 := time.Now()
	r, err := cachedDoH(context.Background(), name, dnswire.TypeA, q)
	if err != nil || time.Since(t0) > 20*time.Millisecond {
		t.Fatalf("stale not served at once: %v", err)
	}
	if ip, _ := dnswire.FirstIP(r); ip.As4()[3] != 1 || dnswire.MinTTL(r) != staleTTL {
		t.Fatalf("stale answer %v ttl %d", ip, dnswire.MinTTL(r))
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	r, _ = cachedDoH(context.Background(), name, dnswire.TypeA, q)
	if ip, _ := dnswire.FirstIP(r); ip.As4()[3] != 2 || calls.Load() != 2 {
		t.Fatalf("not refreshed: %v calls=%d", ip, calls.Load())
	}

	expire(k, 61*time.Second+maxStale)
	r, _ = cachedDoH(context.Background(), name, dnswire.TypeA, q)
	if ip, _ := dnswire.FirstIP(r); ip.As4()[3] != 3 || dnswire.MinTTL(r) == staleTTL {
		t.Fatalf("too-stale answer served: %v", ip)
	}

	expire(k, 61*time.Second)
	ClearCache()
	r, _ = cachedDoH(context.Background(), name, dnswire.TypeA, q)
	if ip, _ := dnswire.FirstIP(r); ip.As4()[3] != 4 {
		t.Fatalf("stale survived ClearCache: %v", ip)
	}
}

func TestRemoteNotServedStale(t *testing.T) {
	var calls atomic.Int32
	withUpstream(t, func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		calls.Add(1)
		_, qt, qEnd, _ := dnswire.Question(q)
		return dnswire.Answer(q, qEnd, 0, qt, 300, []byte{8, 8, 8, 8}), nil
	})
	q := dnswire.Query("r.example", dnswire.TypeA)
	_, _ = remoteDoH(context.Background(), "r.example", dnswire.TypeA, q)
	expire(cacheKey{"r.example", dnswire.TypeA, true}, 301*time.Second)
	r, _ := remoteDoH(context.Background(), "r.example", dnswire.TypeA, q)
	if calls.Load() != 2 || dnswire.MinTTL(r) == staleTTL {
		t.Fatal("remote answer served stale")
	}
}

func TestNegativeCaching(t *testing.T) {
	var calls atomic.Int32
	soaMin := uint32(5)
	withUpstream(t, func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		calls.Add(1)
		_, qt, qEnd, _ := dnswire.Question(q)
		return dnswire.Answer(q, qEnd, 0, qt, 0, nil), nil
	})
	q := dnswire.Query("v4only.example", dnswire.TypeAAAA)
	for i := 0; i < 3; i++ {
		_, _ = cachedDoH(context.Background(), "v4only.example", dnswire.TypeAAAA, q)
	}
	if calls.Load() != 1 {
		t.Fatalf("NOERROR-empty not cached: %d", calls.Load())
	}
	cacheMu.Lock()
	e := dnsCache[cacheKey{"v4only.example", dnswire.TypeAAAA, false}]
	cacheMu.Unlock()
	if d := time.Until(e.expires); d < 29*time.Second || d > 31*time.Second || e.stale != e.expires {
		t.Fatalf("negative ttl %v (want 30s floor, no stale)", d)
	}
	_ = soaMin
	if cacheTTL([]byte{0, 0, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0}) != 0 {
		t.Fatal("SERVFAIL cached")
	}
}
