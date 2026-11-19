package outbound

import (
	"testing"

	"arc/core/internal/store"
	"arc/core/internal/store/storetest"
)

func TestCatalogDoesNotPinIPs(t *testing.T) {
	storetest.Require(t)
	c := store.Get()
	if len(c.StaticDoHIP) != 0 || len(c.StaticEndpointIP) != 0 {
		t.Fatalf("catalog must not pin DoH or endpoint IPs: doh=%d ep=%d", len(c.StaticDoHIP), len(c.StaticEndpointIP))
	}
}

func TestProfilesUseHTTPSDoH(t *testing.T) {
	storetest.Require(t)
	for _, proto := range []store.Protocol{store.ProtoAnyTLS, store.ProtoTrojan} {
		for _, raw := range store.Get().Profile(proto).DoHUrls {
			_ = dohHost(t, raw)
		}
	}
}
