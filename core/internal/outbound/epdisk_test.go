package outbound

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"arc/core/internal/store"
	"arc/core/internal/store/storetest"
)

func TestEmptyDataDirHasNoEndpointSeed(t *testing.T) {
	storetest.Require(t)
	dir := t.TempDir()
	SetDataDir(dir)
	if _, err := os.Stat(filepath.Join(dir, "ep_cache.json")); !os.IsNotExist(err) {
		t.Fatalf("expected no ep_cache.json on clean install, err=%v", err)
	}
	a := &store.Get().Regions[0]
	for i := range store.Get().Endpoints {
		if _, ok := diskEP(a, uint8(i), store.ProtoAnyTLS); ok {
			t.Fatalf("ep %d should not be seeded without a runtime cache", i)
		}
	}
}

func TestClearEndpointCachePreservesDisk(t *testing.T) {
	storetest.Require(t)
	dir := t.TempDir()
	SetDataDir(dir)
	a := &store.Get().Regions[0]
	ip := netip.MustParseAddr("203.0.113.50")
	gen := flowGen.Load()
	n := &a.Nodes[0]
	saveDiskEP(a, n.EpID, n.Proto, ip, gen)
	path := filepath.Join(dir, "ep_cache.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("ep_cache.json not written:", err)
	}
	ClearEndpointCache()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("ep_cache.json removed by ClearEndpointCache:", err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	key := epKey(a, n.EpID, n.Proto)
	if m[key] != ip.String() {
		t.Fatalf("disk map after clear: %v", m)
	}
	got, ok := diskEP(a, n.EpID, n.Proto)
	if !ok || got != ip {
		t.Fatalf("in-memory disk map lost: got %v ok=%v", got, ok)
	}
}

func TestDiskEndpointScopedByProto(t *testing.T) {
	storetest.Require(t)
	dir := t.TempDir()
	SetDataDir(dir)
	a := &store.Get().Regions[0]
	n := &a.Nodes[0]
	other := store.ProtoAnyTLS
	if n.Proto == other {
		other = store.ProtoTrojan
	}
	saveDiskEP(a, n.EpID, n.Proto, netip.MustParseAddr("203.0.113.51"), flowGen.Load())
	if _, ok := diskEP(a, n.EpID, other); ok {
		t.Fatal("endpoint address shared across protocols")
	}
	if err := os.WriteFile(filepath.Join(dir, "ep_cache.json"), []byte(`{"legacy|host":"203.0.113.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	SetDataDir(dir)
	epDiskMu.Lock()
	left := len(epDisk)
	epDiskMu.Unlock()
	if left != 0 {
		t.Fatal("unscoped disk entry kept")
	}
}
