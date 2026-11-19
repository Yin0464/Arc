package main

import (
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"arc/core/internal/router"
)

// rulesDir is the rule-library dir the embedded tables were generated from.
// build.sh points ARC_RULES at its freshly fetched copy; after
// `go run ./cmd/codegen -fixture` use the committed testdata/rules. Without
// it these tests cannot know what the tables should contain, so they skip.
func rulesDir(t *testing.T) string {
	t.Helper()
	d := os.Getenv("ARC_RULES")
	if d == "" {
		t.Skip("ARC_RULES not set")
	}
	abs, err := filepath.Abs(d)
	if err != nil {
		t.Fatal(err)
	}
	fx, _ := filepath.Abs("testdata/rules")
	fixture = abs == fx
	t.Cleanup(func() { fixture = false })
	return abs
}

func TestGoogleFirstEquivalence(t *testing.T) {
	rawDir = rulesDir(t)
	foreign, cn := map[string]bool{}, map[string]bool{}
	fList, cList := fusedDomainLists()
	for _, d := range fList {
		foreign[d] = true
	}
	for _, d := range cList {
		cn[d] = true
	}
	anySuffix := func(set map[string]bool, d string) bool {
		if set["="+d] {
			return true
		}
		for i := -1; i < len(d); i++ {
			if (i == -1 || d[i] == '.') && set[d[i+1:]] {
				return true
			}
		}
		return false
	}
	naive := func(d string) router.Action {
		switch {
		case anySuffix(foreign, d):
			return router.ActionProxy
		case anySuffix(cn, d):
			return router.ActionDirect
		}
		return router.ActionUnknown
	}
	var names []string
	for d := range foreign {
		d = strings.TrimPrefix(d, "=")
		names = append(names, d, "a1."+d, "cn."+d)
	}
	i := 0
	for d := range cn {
		if i++; i > 20000 {
			break
		}
		d = strings.TrimPrefix(d, "=")
		names = append(names, d, "www."+d, "google."+d)
	}
	r := rand.New(rand.NewPCG(1, 0))
	tlds := []string{"com", "cn", "net", "org", "com.cn", "io"}
	for range 20000 {
		b := make([]byte, 3+r.IntN(10))
		for j := range b {
			b[j] = 'a' + byte(r.IntN(26))
		}
		names = append(names, string(b)+"."+tlds[r.IntN(len(tlds))])
	}
	if f, err := os.ReadFile("/workspace/corpus/input.txt"); err == nil {
		for _, l := range strings.Fields(string(f)) {
			if !strings.HasPrefix(l, "ip:") {
				names = append(names, l)
			}
		}
	}
	bad := 0
	for _, d := range names {
		if got, want := router.MatchDomain(d), naive(d); got != want {
			if bad++; bad < 10 {
				t.Errorf("%s: %v want %v", d, got, want)
			}
		}
	}
	t.Logf("%d names, %d mismatches", len(names), bad)
}

func TestNotCNAttrSplit(t *testing.T) {
	rawDir = rulesDir(t)
	noAtCN, atCN := geolocationNotCN()
	noSet, atSet := map[string]bool{}, map[string]bool{}
	for _, d := range noAtCN {
		noSet[d] = true
	}
	for _, d := range atCN {
		atSet[d] = true
	}
	if !noSet["github.com"] {
		t.Fatal("github.com should be !cn without @cn")
	}
	if !atSet["amazon.cn"] || !atSet["akamai.com"] {
		t.Fatal("amazon.cn / akamai.com should be !cn with @cn")
	}
	goog := map[string]bool{}
	for _, d := range GoogleDomains() {
		goog[d] = true
	}
	foreign, cn := fusedDomainLists()
	fSet, cSet := map[string]bool{}, map[string]bool{}
	for _, d := range foreign {
		fSet[d] = true
	}
	for _, d := range cn {
		cSet[d] = true
	}
	if !fSet["github.com"] {
		t.Fatal("!cn non-@cn must land in foreign")
	}
	if cSet["github.com"] {
		t.Fatal("foreign must outrank cn for github.com")
	}
	// amazon.cn may be parent-deduped under bare TLD "cn" from china list; runtime still directs.
	if router.MatchDomain("amazon.cn") != router.ActionDirect {
		t.Fatal("!cn @cn under .cn must direct (via @cn tier or parent cn)")
	}
	if goog["akamai.com"] {
		if !fSet["akamai.com"] {
			t.Fatal("google∩@cn must stay foreign")
		}
	} else if !cSet["akamai.com"] {
		t.Fatal("!cn @cn without google must land in cn set")
	}
	if router.MatchDomain("akamai.com") != router.ActionDirect && !fSet["akamai.com"] {
		t.Fatal("akamai.com @cn must direct unless foreign/google")
	}
	if router.MatchDomain("github.com") != router.ActionProxy {
		t.Fatal("!cn non-@cn must proxy at runtime")
	}
}

func TestGoogleFirstIPEquivalence(t *testing.T) {
	rawDir = rulesDir(t)
	load := func(f string) (out []netip.Prefix) {
		for _, l := range readLines(rawDir + "/" + f) {
			if p, err := netip.ParsePrefix(strings.TrimSpace(l)); err == nil {
				out = append(out, p.Masked())
			}
		}
		return
	}
	goog := load("geoip_google.txt")
	cn := append(append(load("geoip_cn.txt"), load("operator_china.txt")...), load("operator_china6.txt")...)
	if len(goog) == 0 || len(cn) == 0 {
		t.Fatal("rule lists empty")
	}
	in := func(ps []netip.Prefix, a netip.Addr) bool {
		for _, p := range ps {
			if p.Bits() > 64 && a.Is6() {
				p = netip.PrefixFrom(p.Addr(), 64).Masked()
			}
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	r := rand.New(rand.NewPCG(2, 0))
	var addrs []netip.Addr
	pick := func(p netip.Prefix) netip.Addr {
		b := p.Addr().AsSlice()
		for i := range b {
			if i*8 >= p.Bits() {
				b[i] = byte(r.IntN(256))
			}
		}
		a, _ := netip.AddrFromSlice(b)
		return a
	}
	for i := 0; i < 3000; i++ {
		addrs = append(addrs, pick(goog[r.IntN(len(goog))]), pick(cn[r.IntN(len(cn))]))
		var b [4]byte
		for i := range b {
			b[i] = byte(r.IntN(256))
		}
		addrs = append(addrs, netip.AddrFrom4(b))
	}
	bad := 0
	for _, a := range addrs {
		if router.MatchIP(a) == router.ActionLAN {
			continue
		}
		want := router.ActionProxy
		if !in(goog, a) && in(cn, a) {
			want = router.ActionDirect
		}
		if got := router.MatchIP(a); got != want {
			if bad++; bad < 10 {
				t.Errorf("%s: %v want %v", a, got, want)
			}
		}
	}
	t.Logf("%d addrs, %d mismatches", len(addrs), bad)
}
