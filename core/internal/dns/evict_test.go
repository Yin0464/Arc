package dns

import (
	"fmt"
	"testing"
	"time"
)

func TestEvictDropsStaleThenSoonestStale(t *testing.T) {
	ClearCache()
	t.Cleanup(ClearCache)
	now := time.Now()
	cacheMu.Lock()
	for i := 0; i < maxCache; i++ {
		stale := now.Add(time.Duration(i+1) * time.Second)
		if i < 10 {
			stale = now.Add(-time.Second) // already past serve-stale
		}
		dnsCache[cacheKey{fmt.Sprintf("n%d.example", i), 1, false}] = cacheEntry{expires: stale, stale: stale}
	}
	evictLocked(now)
	n := len(dnsCache)
	cacheMu.Unlock()
	if n != maxCache-10 {
		t.Fatalf("stale pass left %d, want %d", n, maxCache-10)
	}

	cacheMu.Lock()
	for i := 0; i < 10; i++ {
		dnsCache[cacheKey{fmt.Sprintf("m%d.example", i), 1, false}] = cacheEntry{stale: now.Add(time.Hour)}
	}
	evictLocked(now)
	_, oldest := dnsCache[cacheKey{"n10.example", 1, false}]
	_, newest := dnsCache[cacheKey{fmt.Sprintf("n%d.example", maxCache-1), 1, false}]
	n = len(dnsCache)
	cacheMu.Unlock()
	if want := maxCache - maxCache/8; n != want || oldest || !newest {
		t.Fatalf("len %d want %d, oldest kept %v, newest kept %v", n, want, oldest, newest)
	}
}

func BenchmarkCacheInsertFull(b *testing.B) {
	ClearCache()
	b.Cleanup(ClearCache)
	now := time.Now()
	cacheMu.Lock()
	defer cacheMu.Unlock()
	for i := 0; i < b.N; i++ {
		if len(dnsCache) >= maxCache {
			evictLocked(now)
		}
		dnsCache[cacheKey{fmt.Sprintf("b%d", i), 1, false}] = cacheEntry{stale: now.Add(time.Duration(i) * time.Millisecond)}
	}
}
