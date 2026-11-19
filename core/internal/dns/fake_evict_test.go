package dns

import (
	"fmt"
	"testing"
)

func TestFakeIPFullPoolEvictsOldest(t *testing.T) {
	p := &FakeIPPool{cursor: 1, domainToIdx: make(map[string]uint16, 65536)}
	const n = 65533
	for i := 0; i < n; i++ {
		p.Allocate(fmt.Sprintf("h%d.example", i), false)
	}
	oldest := "h0.example"
	newest := fmt.Sprintf("h%d.example", n-1)
	if _, ok := p.domainToIdx[oldest]; !ok {
		t.Fatal("oldest missing before eviction")
	}
	if _, ok := p.domainToIdx[newest]; !ok {
		t.Fatal("newest missing before eviction")
	}
	p.Allocate("fresh.example", false)
	if _, ok := p.domainToIdx[oldest]; ok {
		t.Fatal("full pool evicted a newer name and kept the oldest")
	}
	if _, ok := p.domainToIdx[newest]; !ok {
		t.Fatal("full pool evicted the newest name")
	}
	idx := p.domainToIdx["fresh.example"]
	if idx == 0 {
		t.Fatal("fresh name was not installed")
	}
	if got, ok := p.Lookup(slotToAddr(idx, false)); !ok || got != "fresh.example" {
		t.Fatalf("fresh slot resolves to %q ok=%v", got, ok)
	}
}
