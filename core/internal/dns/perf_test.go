package dns

import (
	"testing"

	"arc/core/internal/dnswire"
	"arc/core/internal/router"
)

func BenchmarkFakeLookup(b *testing.B) {
	ip := GlobalFakeIP.Allocate("lookup.example", false)
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := GlobalFakeIP.Lookup(ip); !ok {
			b.Fatal("miss")
		}
	}
}

func BenchmarkFakeLookupParallel(b *testing.B) {
	ip := GlobalFakeIP.Allocate("lookup.example", false)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok := GlobalFakeIP.Lookup(ip); !ok {
				b.Fatal("miss")
			}
		}
	})
}

func BenchmarkTryFastFakeIP(b *testing.B) {
	const name = "speed.example"
	router.LearnDomain(name, router.ActionProxy)
	q := dnswire.Query(name, dnswire.TypeA)
	b.ReportAllocs()
	for b.Loop() {
		if r, ok := TryFastFakeIP(q); !ok || len(r) < 12 {
			b.Fatal("miss")
		}
	}
}
