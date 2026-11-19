package router

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestMatchDomainLANCase(t *testing.T) {
	for _, d := range []string{"Printer.LOCAL", "foo.Lan", "x.ARPA.", "a.Local."} {
		if MatchDomain(d) != ActionLAN || !IsLANDomain(d) {
			t.Fatalf("%s not LAN", d)
		}
	}
	LearnDomain("Zz-Case.Test", ActionDirect)
	t.Cleanup(ClearLearned)
	if MatchDomain("zz-case.test") != ActionDirect || MatchDomain("ZZ-CASE.TEST") != ActionDirect {
		t.Fatal("learned name is case-sensitive")
	}
}

func TestLearnedTTL(t *testing.T) {
	ClearLearned()
	defer func(f func() int64) { nowUnix = f; ClearLearned() }(nowUnix)
	now := int64(1_000_000)
	nowUnix = func() int64 { return now }
	LearnDomain("a.test", ActionDirect)
	LearnDomainFor("b.test", ActionProxy, 6*time.Hour)
	if MatchDomain("a.test") != ActionDirect || MatchDomain("b.test") != ActionProxy {
		t.Fatal("not learned")
	}
	now += int64(6*time.Hour/time.Second) + 1
	if MatchDomain("b.test") != ActionUnknown || MatchDomain("a.test") != ActionDirect {
		t.Fatal("fallback ttl")
	}
	now += int64(LearnTTL / time.Second)
	if MatchDomain("a.test") != ActionUnknown {
		t.Fatal("ttl")
	}
}

func TestLearnedClockKeepsHot(t *testing.T) {
	ClearLearned()
	defer ClearLearned()
	for i := 0; i < maxLearned; i++ {
		LearnDomain(fmt.Sprintf("d%d.test", i), ActionProxy)
	}
	for i := 0; i < maxLearned; i++ {
		slots[learned[fmt.Sprintf("d%d.test", i)]].ref.Store(false)
	}
	MatchDomain("d0.test")
	MatchDomain("d1.test")
	for i := 0; i < 100; i++ {
		LearnDomain(fmt.Sprintf("n%d.test", i), ActionProxy)
	}
	if len(learned) != maxLearned {
		t.Fatal(len(learned))
	}
	if MatchDomain("d0.test") != ActionProxy || MatchDomain("d1.test") != ActionProxy {
		t.Fatal("hot entries evicted")
	}
	if MatchDomain("d2.test") != ActionUnknown {
		t.Fatal("cold entry kept")
	}
}

func TestLearnedPersist(t *testing.T) {
	ClearLearned()
	defer ClearLearned()
	LearnDomain("p.test", ActionProxy)
	LearnDomain("c.test", ActionDirect)
	b := DumpLearned()
	ClearLearned()
	LearnDomain("c.test", ActionProxy)
	if n := LoadLearned(append(b, []byte("garbage\n1 2 old.test\n")...)); n != 2 {
		t.Fatalf("loaded %d", n)
	}
	if MatchDomain("p.test") != ActionProxy || MatchDomain("c.test") != ActionProxy || MatchDomain("old.test") != ActionUnknown {
		t.Fatal("merge")
	}

	dir := t.TempDir()
	learnPath = filepath.Join(dir, "learned.txt")
	defer func() { learnPath = "" }()
	select {
	case <-loadDone:
	default:
		close(loadDone)
	}
	if err := FlushLearned(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(learnPath)
	ClearLearned()
	if LoadLearned(got) != 3-1 {
		t.Fatal("file")
	}
}

func TestLearnedRace(t *testing.T) {
	ClearLearned()
	defer ClearLearned()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				d := fmt.Sprintf("r%d.test", (i*7+g)%12000)
				LearnDomain(d, ActionProxy)
				MatchDomain(d)
				if i%1000 == 0 {
					_ = DumpLearned()
				}
			}
		}()
	}
	wg.Wait()
}

func BenchmarkLoadLearned(b *testing.B) {
	ClearLearned()
	for i := 0; i < maxLearned; i++ {
		LearnDomain(fmt.Sprintf("host%d.example%d.com", i, i%97), Action(1+i%2))
	}
	data := DumpLearned()
	b.Logf("file bytes for %d entries: %d", maxLearned, len(data))
	b.ReportAllocs()
	for b.Loop() {
		ClearLearned()
		LoadLearned(data)
	}
}

func BenchmarkMatchLearned(b *testing.B) {
	ClearLearned()
	LearnDomain("hot.example.com", ActionProxy)
	b.ReportAllocs()
	for b.Loop() {
		sink = MatchDomain("hot.example.com") == ActionProxy
	}
}

func TestLearnedStampDiscardsOld(t *testing.T) {
	if s := learnedStamp(); len(s) < 5 || s[:3] != "#v6" {
		t.Fatalf("stamp %q", s)
	}
}

func TestCNListBeatsLearned(t *testing.T) {
	ClearLearned()
	defer ClearLearned()
	LearnDomainFor("vd.l.qq.com", ActionProxy, 6*time.Hour)
	if a := MatchDomain("vd.l.qq.com"); a != ActionDirect {
		t.Fatalf("CN-list name overridden by learned proxy: %v", a)
	}
}

func TestDirectIP(t *testing.T) {
	a := netip.MustParseAddr("23.46.228.79")
	if IsDirectIP(a) {
		t.Fatal("unexpected")
	}
	NoteDirectIP(a, time.Minute)
	if !IsDirectIP(a) || !IsDirectIP(netip.AddrFrom16(a.As16())) {
		t.Fatal("not remembered")
	}
}
