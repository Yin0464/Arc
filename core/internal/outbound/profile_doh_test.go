package outbound

import (
	"net/url"
	"strings"
	"testing"
	"unicode"

	"arc/core/internal/store"
	"arc/core/internal/store/storetest"
)

func dohHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		t.Fatalf("DoH URL is not https: %q", raw)
	}
	return strings.ToLower(u.Hostname())
}

// Each protocol resolves its endpoints through its own source's DoH servers:
// the two profiles must not share a DoH host.
func TestUpstreamProfileDoHIsolatedByProto(t *testing.T) {
	storetest.Require(t)
	anyP := store.Get().Profile(store.ProtoAnyTLS)
	trojanP := store.Get().Profile(store.ProtoTrojan)
	if len(anyP.DoHUrls) == 0 || len(trojanP.DoHUrls) == 0 {
		t.Fatal("empty DoHUrls on upstream profile")
	}
	hosts := map[string]bool{}
	for _, u := range anyP.DoHUrls {
		hosts[dohHost(t, u)] = true
	}
	for _, u := range trojanP.DoHUrls {
		if hosts[dohHost(t, u)] {
			t.Fatal("AnyTLS and Trojan profiles share a DoH host")
		}
	}
}

func TestResolveEndpointUsesNodeProtoDoH(t *testing.T) {
	storetest.Require(t)
	if len(store.Get().Regions) == 0 {
		t.Fatal("no regions")
	}
	r := &store.Get().Regions[0]
	var trojanNode, anyNode *store.Node
	for i := range r.Nodes {
		n := &r.Nodes[i]
		if n.Proto == store.ProtoTrojan && trojanNode == nil {
			trojanNode = n
		}
		if n.Proto == store.ProtoAnyTLS && anyNode == nil {
			anyNode = n
		}
	}
	if trojanNode == nil || anyNode == nil {
		t.Fatal("need both Trojan and AnyTLS nodes in region 0")
	}

	if r.Nodes[0].Proto != store.ProtoTrojan {
		t.Fatalf("first node proto=%s want Trojan", r.Nodes[0].ProtoLabel())
	}

	if store.Get().Profile(trojanNode.Proto) != store.Get().Profile(store.ProtoTrojan) {
		t.Fatal("Trojan node does not map to Trojan profile")
	}
	if store.Get().Profile(anyNode.Proto) != store.Get().Profile(store.ProtoAnyTLS) {
		t.Fatal("AnyTLS node does not map to AnyTLS profile")
	}

	_ = r.Name
}

func TestRegionsTrojanThenAnyTLS(t *testing.T) {
	storetest.Require(t)
	want := []string{"香港", "日本", "台湾", "新加坡", "其他"}
	if len(store.Get().Regions) != len(want) {
		t.Fatalf("regions=%d want %d", len(store.Get().Regions), len(want))
	}
	for i, name := range want {
		r := store.Get().Regions[i]
		if r.Name != name {
			t.Fatalf("region[%d]=%s want %s", i, r.Name, name)
		}
		if name == "其他" {
			var prev string
			seenAny := false
			for _, n := range r.Nodes {
				country := n.Name
				if j := indexHanSuffix(n.Name); j > 0 {
					country = n.Name[:j]
				}
				if country != prev {
					prev = country
					seenAny = false
				}
				if n.Proto == store.ProtoAnyTLS {
					seenAny = true
				}
				if n.Proto == store.ProtoTrojan && seenAny {
					t.Fatalf("%s: Trojan after AnyTLS (order broken at %s)", r.Name, n.Name)
				}
			}
			continue
		}
		seenAny := false
		for _, n := range r.Nodes {
			if n.Proto == store.ProtoAnyTLS {
				seenAny = true
			}
			if n.Proto == store.ProtoTrojan && seenAny {
				t.Fatalf("%s: Trojan after AnyTLS (order broken at %s)", r.Name, n.Name)
			}
		}
	}
}

// indexHanSuffix is where the leading country name ends.
func indexHanSuffix(name string) int {
	for i, r := range name {
		if !unicode.Is(unicode.Han, r) {
			return i
		}
	}
	return -1
}
