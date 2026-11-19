package store_test

import (
	"arc/core/internal/store"
	"arc/core/internal/store/storetest"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

func TestMain(m *testing.M) {
	if store.Loaded() || len(store.Get().Regions) != 0 {
		fmt.Fprintln(os.Stderr, "empty catalog expected before tests")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestCatalogShape(t *testing.T) {
	storetest.Require(t)
	Regions, Endpoints := store.Get().Regions, store.Get().Endpoints
	want := []string{"香港", "日本", "台湾", "新加坡", "其他"}
	if len(Regions) != len(want) {
		t.Fatalf("regions = %d", len(Regions))
	}
	for i := range Regions {
		r := &Regions[i]
		if r.Name != want[i] {
			t.Fatalf("region %d = %q, want %q", i, r.Name, want[i])
		}
		if len(r.Nodes) == 0 {
			t.Fatalf("%s: no nodes", r.Name)
		}
		checkRegionCountries(t, r, Endpoints)
	}
}

func checkNodeBasics(t *testing.T, r *store.Region, n *store.Node, endpoints []string, names map[string]bool) {
	t.Helper()
	if names[n.Name] {
		t.Fatalf("duplicate name %q", n.Name)
	}
	names[n.Name] = true
	if n.Proto != store.ProtoAnyTLS && n.Proto != store.ProtoTrojan {
		t.Fatalf("%s: bad proto", n.Name)
	}
	if int(n.Opt) >= len(r.Opts) || int(n.EpID) >= len(endpoints) || n.Port == 0 {
		t.Fatalf("%s: bad opt/ep/port", n.Name)
	}
	if r.NodeSNI(n) == "" {
		t.Fatalf("%s: empty SNI", n.Name)
	}
}

var primary = map[string]bool{"香港": true, "日本": true, "台湾": true, "新加坡": true}

// A primary tab holds only its own country; 其他 holds none of them, with
// each country's nodes together.
func checkRegionCountries(t *testing.T, r *store.Region, endpoints []string) {
	t.Helper()
	names := map[string]bool{}
	seen := map[string]bool{}
	prev := ""
	for k := range r.Nodes {
		n := &r.Nodes[k]
		checkNodeBasics(t, r, n, endpoints, names)
		country := leadingHan(n.Name)
		if country == "" {
			t.Fatalf("%s: name does not start with a country", n.Name)
		}
		if primary[r.Name] {
			if !strings.HasPrefix(country, r.Name) {
				t.Fatalf("%s in %s", n.Name, r.Name)
			}
			continue
		}
		for p := range primary {
			if strings.HasPrefix(country, p) {
				t.Fatalf("%s: primary country in %s", n.Name, r.Name)
			}
		}
		if country != prev {
			if seen[country] {
				t.Fatalf("%s: country not grouped together", n.Name)
			}
			seen[country], prev = true, country
		}
	}
}

func leadingHan(s string) string {
	for i, r := range s {
		if !unicode.Is(unicode.Han, r) {
			return s[:i]
		}
	}
	return s
}

func TestProfileByProto(t *testing.T) {
	storetest.Require(t)
	c := store.Get()
	for _, p := range []store.Protocol{store.ProtoAnyTLS, store.ProtoTrojan} {
		pr := c.Profile(p)
		if len(pr.DoHUrls) == 0 || len(pr.Key) != store.KeyLen[p] {
			t.Fatalf("protocol %d: profile without DoH or key", p)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("Profile(0) must panic")
		}
	}()
	c.Profile(0)
}

var sample = `{"version":3,"static_doh_ip":{},"static_endpoint_ip":{},"endpoints":["ep.example"],
"profiles":[{"proto":1,"doh":["https://a.example/dns-query"],"key":"` + keyB64(32, 1) + `"},
{"proto":2,"doh":["https://t.example/dns-query"],"key":"` + keyB64(56, 2) + `"}],
"regions":[{"name":"香港","sni":"s.example","opts":[{"udp":true}],"nodes":[
{"name":"香港 01|x","port":443,"ep":0,"proto":2},{"name":"a|b|c","port":8443,"ep":0,"proto":1}]}]}`

func keyB64(n int, first byte) string {
	b := make([]byte, n)
	b[0] = first
	return base64.StdEncoding.EncodeToString(b)
}

func TestParseRoundTripAndUIJSON(t *testing.T) {
	c, err := store.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := store.Parse(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, c2) {
		t.Fatal("Encode/Parse not lossless")
	}
	var ui []struct {
		Name  string `json:"name"`
		Nodes []struct {
			Name  string `json:"name"`
			Proto string `json:"proto"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(c.UIJSON(), &ui); err != nil {
		t.Fatal(err)
	}
	if len(ui) != 1 || ui[0].Name != "香港" || len(ui[0].Nodes) != 2 ||
		ui[0].Nodes[0].Name != "香港 01|x" || ui[0].Nodes[0].Proto != "Trojan" ||
		ui[0].Nodes[1].Name != "a|b|c" || ui[0].Nodes[1].Proto != "AnyTLS" {
		t.Fatalf("UIJSON = %+v", ui)
	}
}

func TestParseRejectsBadTables(t *testing.T) {
	trojanProfile := `{"proto":2,"doh":["https://t.example/dns-query"],"key":"` + keyB64(56, 2) + `"}`
	for name, mut := range map[string]func(string) string{
		"version":   func(s string) string { return strings.Replace(s, `"version":3`, `"version":2`, 1) },
		"endpoint":  func(s string) string { return strings.Replace(s, `"ep":0,"proto":2`, `"ep":1,"proto":2`, 1) },
		"proto":     func(s string) string { return strings.Replace(s, `"proto":2}`, `"proto":3}`, 1) },
		"port":      func(s string) string { return strings.Replace(s, `"port":443`, `"port":0`, 1) },
		"unknown":   func(s string) string { return strings.Replace(s, `"version":3`, `"version":3,"extra":true`, 1) },
		"transport": func(s string) string { return strings.Replace(s, `"udp":true`, `"udp":true,"network":"ws"`, 1) },
		"v2 fields": func(s string) string { return strings.Replace(s, `"profiles":`, `"trojan":{},"profiles":`, 1) },
		"dup profile": func(s string) string {
			return strings.Replace(s, trojanProfile, trojanProfile+","+trojanProfile, 1)
		},
		"no profile for node": func(s string) string { return strings.Replace(s, ",\n"+trojanProfile, "", 1) },
		"profile proto":       func(s string) string { return strings.Replace(s, `{"proto":2,"doh"`, `{"proto":3,"doh"`, 1) },
		"no doh": func(s string) string {
			return strings.Replace(s, `"doh":["https://t.example/dns-query"]`, `"doh":[]`, 1)
		},
		"zero key":  func(s string) string { return strings.Replace(s, keyB64(56, 2), keyB64(56, 0), 1) },
		"short key": func(s string) string { return strings.Replace(s, keyB64(56, 2), keyB64(32, 2), 1) },
		"no profiles": func(s string) string {
			return strings.Replace(s, s[strings.Index(s, `"profiles":`):strings.Index(s, `"regions"`)], `"profiles":[],`, 1)
		},
		"garbage": func(string) string { return "{" },
	} {
		if _, err := store.Parse([]byte(mut(sample))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseAllowsMissingUnusedProfile(t *testing.T) {
	s := strings.Replace(sample, `{"name":"香港 01|x","port":443,"ep":0,"proto":2},`, "", 1)
	s = strings.Replace(s, ",\n"+`{"proto":2,"doh":["https://t.example/dns-query"],"key":"`+keyB64(56, 2)+`"}`, "", 1)
	c, err := store.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Regions[0].Nodes) != 1 || c.Regions[0].Nodes[0].Proto != store.ProtoAnyTLS {
		t.Fatalf("nodes %+v", c.Regions[0].Nodes)
	}
	if len(c.Profile(store.ProtoTrojan).Key) != 0 {
		t.Fatal("missing Trojan profile should read as empty")
	}
}
