package dns

import (
	"net/netip"
	"testing"
	"time"

	"arc/core/internal/dnswire"
)

func TestSetUnderlyingFlushesCacheOnChange(t *testing.T) {
	ClearCache()
	defer SetUnderlying("", -1)
	const name = "flush.example"
	k := cacheKey{name, dnswire.TypeA, false}
	cacheMu.Lock()
	dnsCache[k] = cacheEntry{wire: []byte{9, 9, 9}, expires: time.Now().Add(time.Minute), stale: time.Now().Add(2 * time.Minute)}
	cacheMu.Unlock()
	SetUnderlying("8.8.8.8", 0)
	cacheMu.Lock()
	_, ok := dnsCache[k]
	cacheMu.Unlock()
	if ok {
		t.Fatal("DNS list change should flush cache")
	}
	cacheMu.Lock()
	dnsCache[k] = cacheEntry{wire: []byte{9, 9, 9}, expires: time.Now().Add(time.Minute), stale: time.Now().Add(2 * time.Minute)}
	cacheMu.Unlock()
	SetUnderlying("8.8.8.8", 0)
	cacheMu.Lock()
	_, ok = dnsCache[k]
	cacheMu.Unlock()
	if !ok {
		t.Fatal("identical DNS list should not flush")
	}
	SetUnderlying("8.8.4.4", 0)
	cacheMu.Lock()
	_, ok = dnsCache[k]
	cacheMu.Unlock()
	if ok {
		t.Fatal("DNS server change should flush cache")
	}
}

func TestDnsListChangedHelpers(t *testing.T) {
	if dnsListChanged(nil, nil) {
		t.Fatal("nil to empty")
	}
	a := netip.MustParseAddrPort("1.1.1.1:53")
	list := []netip.AddrPort{a}
	if !dnsListChanged(nil, list) {
		t.Fatal("nil to list")
	}
	prev := list
	if dnsListChanged(&prev, list) {
		t.Fatal("same list")
	}
}
