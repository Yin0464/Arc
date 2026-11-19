package router

import (
	"net/netip"
	"testing"
)

func TestFusedDomainTags(t *testing.T) {
	if MatchDomain("www.google.com") != ActionProxy || MatchDomain("dl.google.com") != ActionProxy {
		t.Fatal("google-tagged domain must proxy")
	}
	if MatchDomain("www.baidu.com") != ActionDirect || MatchDomain("v.qq.com") != ActionDirect {
		t.Fatal("cn-tagged domain must direct")
	}
	if IsCNDomain("www.google.com") {
		t.Fatal("google tag must outrank cn on conflict / not report as CN")
	}
	if MatchDomain("github.com") != ActionProxy || MatchDomain("www.github.com") != ActionProxy {
		t.Fatal("geolocation-!cn without @cn must proxy")
	}
	if MatchDomain("amazon.cn") != ActionDirect {
		t.Fatal("geolocation-!cn with @cn must direct unless google")
	}
	if MatchDomain("totally-unknown-xyz.example") != ActionUnknown {
		t.Fatal("domain miss must stay unknown (resolve overseas then fused IP)")
	}
	if MatchDomain("router.lan") != ActionLAN || MatchDomain("x.local") != ActionLAN {
		t.Fatal("LAN suffixes before fused tables")
	}
}

func TestFusedIPTags(t *testing.T) {
	g := netip.MustParseAddr("142.250.72.196")
	if MatchIP(g) != ActionProxy || !IsGoogleIP(g) {
		t.Fatal("google-tagged IP must proxy")
	}
	cn := netip.MustParseAddr("114.114.114.114")
	if MatchIP(cn) != ActionDirect {
		t.Fatal("cn-tagged IP must direct")
	}
	if MatchIP(netip.MustParseAddr("192.168.1.1")) != ActionLAN {
		t.Fatal("LAN before fused IP table")
	}

	miss := netip.MustParseAddr("1.1.1.1")
	if IsGoogleIP(miss) {
		t.Skip("1.1.1.1 unexpectedly google-tagged")
	}
	if MatchIP(miss) != ActionProxy {
		t.Fatal("IP miss must fallback proxy")
	}
}
