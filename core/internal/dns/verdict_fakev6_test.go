package dns

import (
	"net/netip"
	"testing"

	"arc/core/internal/dnswire"
	"arc/core/internal/router"
)

func TestVerdictPrivateAnswerStaysProxied(t *testing.T) {
	q := dnswire.Query("rebind.example.com", dnswire.TypeA)
	_, _, qEnd, _ := dnswire.Question(q)
	for _, a := range []string{"192.168.1.10", "10.0.0.1", "127.0.0.1"} {
		resp := dnswire.Answer(q, qEnd, 0, dnswire.TypeA, 60, netip.MustParseAddr(a).AsSlice())
		if v := verdict(resp, nil); v != router.ActionProxy {
			t.Fatalf("%s: verdict %v, want proxy (rebinding)", a, v)
		}
	}
	resp := dnswire.Answer(q, qEnd, 0, dnswire.TypeA, 60, netip.MustParseAddr("223.5.5.5").AsSlice())
	if v := verdict(resp, nil); v != router.ActionDirect {
		t.Fatalf("mainland answer: verdict %v, want direct", v)
	}
}

func TestFakeV6RangeAndTTL(t *testing.T) {
	ip := GlobalFakeIP.Allocate("v6.example.org", true)
	if !ip.Is6() || ip.As16()[0] != 0xfd || ip.As16()[7] != 0xff {
		t.Fatalf("fake v6 %v not in fdfe:dcba:9876:ff::/112", ip)
	}
	if d, ok := GlobalFakeIP.Lookup(ip); !ok || d != "v6.example.org" {
		t.Fatal("lookup")
	}
	if InFakeRange(netip.MustParseAddr("fc00::1")) {
		t.Fatal("fc00::/16 must no longer be fake")
	}
	if InFakeRange(netip.MustParseAddr("fdfe:dcba:9876::1")) {
		t.Fatal("TUN address must not be fake")
	}
	q := dnswire.Query("www.google.com", dnswire.TypeA)
	r, ok := TryFastFakeIP(q)
	if !ok || dnswire.MinTTL(r) != FakeTTL {
		t.Fatalf("fake TTL = %d, want %d", dnswire.MinTTL(r), FakeTTL)
	}
}

func TestVerdictNoDataIsUnknown(t *testing.T) {
	q := dnswire.Query("v4only.example.cn", dnswire.TypeAAAA)
	_, _, qEnd, _ := dnswire.Question(q)
	resp := dnswire.Answer(q, qEnd, 0, 0, 0, nil)
	if dnswire.AnswerCount(resp) != 0 {
		t.Fatal("fixture is not NODATA")
	}
	if v := verdict(resp, nil); v != router.ActionUnknown {
		t.Fatalf("NODATA verdict %v, want unknown", v)
	}
}
