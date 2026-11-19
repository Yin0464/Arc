package dns

import (
	"context"
	"os"
	"sort"
	"testing"
	"time"

	"arc/core/internal/dnswire"
)

func TestLiveCacheLatency(t *testing.T) {
	if os.Getenv("DNSLIVE") == "" {
		t.Skip("set DNSLIVE=1")
	}
	names := []string{"www.baidu.com", "www.qq.com", "www.taobao.com", "www.jd.com", "www.163.com", "www.bilibili.com", "www.zhihu.com", "www.douyin.com", "www.sohu.com", "www.sina.com.cn"}
	med := func(xs []time.Duration) time.Duration {
		sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
		return xs[len(xs)/2]
	}
	look := func(n string, qt uint16) time.Duration {
		t0 := time.Now()
		if _, err := cachedDoH(context.Background(), n, qt, dnswire.Query(n, qt)); err != nil {
			t.Logf("%s: %v", n, err)
		}
		return time.Since(t0)
	}
	var miss, hit, stale, blocking []time.Duration
	for round := 0; round < 3; round++ {
		ClearCache()
		for _, n := range names {
			miss = append(miss, look(n, dnswire.TypeA))
			hit = append(hit, look(n, dnswire.TypeA))
			k := cacheKey{n, dnswire.TypeA, false}
			expire(k, 601*time.Second)
			stale = append(stale, look(n, dnswire.TypeA))
			time.Sleep(300 * time.Millisecond)
			expire(k, 601*time.Second+maxStale)
			blocking = append(blocking, look(n, dnswire.TypeA))
		}
	}
	t.Logf("A lookups n=%d: miss %v, hit %v, expired(stale-served) %v, expired(blocking, pre-2.6) %v",
		len(miss), med(miss), med(hit), med(stale), med(blocking))
	ClearCache()
	var neg []time.Duration
	for i := 0; i < 10; i++ {
		neg = append(neg, look("www.baidu.com", dnswire.TypeAAAA))
	}
	t.Logf("AAAA www.baidu.com x10: first %v, median %v", neg[0], med(neg[1:]))
}
