package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"arc/core/internal/store"
)

// goldenNodes is the synthetic node table every package test loads when no
// private table is configured (see internal/store/storetest).
const goldenNodes = "../../internal/store/testdata/nodes.json"

func resetEndpoints() {
	endpoints, epIndex, epProto = nil, map[string]int{}, map[string]store.Protocol{}
}

func syntheticInput(t *testing.T) *Input {
	t.Helper()
	in := readInput("testdata/synthetic/input.json")
	for i := range in.Sources {
		in.Sources[i].Sub = filepath.Join("testdata/synthetic", in.Sources[i].Sub)
	}
	return in
}

func syntheticCatalog(t *testing.T) *store.Catalog {
	t.Helper()
	resetEndpoints()
	t.Cleanup(resetEndpoints)
	cat, _ := genNodes(syntheticInput(t))
	return cat
}

// The committed synthetic table must be exactly what codegen makes from the
// synthetic sources. Regenerate with ARC_UPDATE_GOLDEN=1.
func TestSyntheticGolden(t *testing.T) {
	b, err := syntheticCatalog(t).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Parse(b); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ARC_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(goldenNodes, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenNodes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), b) {
		t.Fatal("synthetic node table drifted; rerun with ARC_UPDATE_GOLDEN=1 and review")
	}
}

func TestSyntheticRules(t *testing.T) {
	cat := syntheticCatalog(t)
	var got []string
	for _, r := range cat.Regions {
		for _, n := range r.Nodes {
			got = append(got, r.Name+"/"+n.Name+"/"+n.ProtoLabel())
		}
	}
	want := []string{
		"香港/香港 01/Trojan", "香港/香港 02/Trojan", "香港/香港 03/AnyTLS", "香港/香港住宅 1/AnyTLS",
		"日本/日本 01/AnyTLS",
		"台湾/台湾 01/AnyTLS",
		"新加坡/新加坡 01/Trojan", "新加坡/新加坡 02/AnyTLS",
		// other_first, then the Trojan source's countries, then the AnyTLS source's
		"其他/美国 01/Trojan", "其他/美国住宅 1/AnyTLS", "其他/德国 01/AnyTLS", "其他/韩国 01/AnyTLS",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("nodes:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(cat.Endpoints) != 4 {
		t.Fatalf("endpoints %d", len(cat.Endpoints))
	}
	tro, any := cat.Profiles[0], cat.Profiles[1]
	if tro.Proto != store.ProtoTrojan || len(tro.Key) != 56 || tro.DoHUrls[0] != "https://dns-t.example.invalid/dns-query" {
		t.Fatalf("trojan profile %+v", tro)
	}
	if any.Proto != store.ProtoAnyTLS || len(any.Key) != 32 || any.DoHUrls[0] != "https://dns-a.example.invalid/dns-query" {
		t.Fatalf("anytls profile %+v", any)
	}
}

func TestRegionRegexMismatchPanics(t *testing.T) {
	resetEndpoints()
	t.Cleanup(resetEndpoints)
	in := syntheticInput(t)
	in.Sources[0].RegionRegex = `^<T>\s*(\p{Han}+)X`
	defer func() {
		if recover() == nil {
			t.Fatal("a prefixed name the region regex cannot parse must panic")
		}
	}()
	genNodes(in)
}

func TestMixedPasswordsPanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("different passwords in one source must panic")
		}
	}()
	samePassword([]string{"a", "b"}, "src")
}
