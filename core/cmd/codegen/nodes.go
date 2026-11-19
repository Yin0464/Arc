package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"arc/core/internal/store"
)

// Input is the private bundle's rule set, resolved by tools/private.py emit
// into codegen-input.json. codegen itself knows no node source: everything
// source-specific (file paths, accepted types, name rules) comes from here.
type Input struct {
	SchemaVersion int               `json:"schema_version"`
	Sources       []Source          `json:"sources"`
	Aliases       map[string]string `json:"aliases"`
	OtherFirst    []string          `json:"other_first"`
	Naming        struct {
		Regular     string `json:"regular"`
		Residential string `json:"residential"`
	} `json:"naming"`
	YAMLKeys struct {
		Padding  string `json:"padding"`
		Metadata string `json:"metadata"`
	} `json:"yaml_keys"`
}

// Source is one subscription file and how to read its proxies.
type Source struct {
	ID                string   `json:"id"`
	Proto             string   `json:"proto"` // "anytls" | "trojan"
	Sub               string   `json:"sub"`
	Types             []string `json:"types"`
	NamePrefix        string   `json:"name_prefix"`  // proxies without it are skipped
	RegionRegex       string   `json:"region_regex"` // capture 1 is the country
	CleanFromFirstHan bool     `json:"clean_from_first_han"`
	CleanCutAt        string   `json:"clean_cut_at"`
	ResidentialMatch  string   `json:"residential_match"`
}

const inputSchema = 1

func readInput(path string) *Input {
	b, err := os.ReadFile(path)
	check(err)
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	in := &Input{}
	check(dec.Decode(in))
	if in.SchemaVersion != inputSchema {
		panic(fmt.Sprintf("codegen input schema %d, want %d", in.SchemaVersion, inputSchema))
	}
	if len(in.Sources) == 0 {
		panic("codegen input has no sources")
	}
	for _, t := range []string{in.Naming.Regular, in.Naming.Residential} {
		if !strings.Contains(t, "{country}") || !strings.Contains(t, "{n") {
			panic("naming templates need {country} and {n}")
		}
	}
	seen := map[string]bool{}
	for _, s := range in.Sources {
		if s.Proto != "anytls" && s.Proto != "trojan" {
			panic(fmt.Sprintf("source %s: protocol %q", s.ID, s.Proto))
		}
		if seen[s.Proto] {
			panic(fmt.Sprintf("source %s: one source per protocol", s.ID))
		}
		seen[s.Proto] = true
		if len(s.Types) == 0 {
			panic(fmt.Sprintf("source %s: no accepted types", s.ID))
		}
	}
	return in
}

type node struct {
	name, sni string
	proto     store.Protocol
	ep, port  int
	opt       int
}

type nodeOpts struct {
	fp         string
	alpn       []string
	skip       bool
	udp        bool
	idleCheck  int
	idleTO     int
	minIdle    int
	minIdleSet bool
	padding    string
	metadata   string
}

type regionEmit struct {
	name  string
	opts  []nodeOpts
	nodes []node
}

var (
	endpoints []string
	epIndex   = map[string]int{}
	epProto   = map[string]store.Protocol{}
)

func endpoint(host string, proto store.Protocol) int {
	if i, ok := epIndex[host]; ok {
		if epProto[host] != proto {
			panic(fmt.Sprintf("endpoint %s used by two protocols", host))
		}
		return i
	}
	epIndex[host] = len(endpoints)
	epProto[host] = proto
	endpoints = append(endpoints, host)
	return len(endpoints) - 1
}

type subDoc struct {
	Proxies []map[string]any `yaml:"proxies"`
	DNS     struct {
		Nameserver            []any          `yaml:"nameserver"`
		ProxyServerNameserver []any          `yaml:"proxy-server-nameserver"`
		NameserverPolicy      map[string]any `yaml:"nameserver-policy"`
	} `yaml:"dns"`
}

func readSub(path string) subDoc {
	b, err := os.ReadFile(path)
	check(err)
	var doc subDoc
	check(yaml.Unmarshal(b, &doc))
	return doc
}

func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func boolean(m map[string]any, k string) bool { b, _ := m[k].(bool); return b }

func strList(m map[string]any, k string) (out []string) {
	l, _ := m[k].([]any)
	for _, v := range l {
		out = append(out, fmt.Sprint(v))
	}
	return out
}

func httpsOnly(vals []any) (out []string) {
	for _, v := range vals {
		s := strings.TrimSpace(fmt.Sprint(v))
		if strings.HasPrefix(s, "https://") {
			out = append(out, s)
		}
	}
	return out
}

func dohFromSub(doc subDoc, nodeServers []string) []string {
	if u := httpsOnly(doc.DNS.ProxyServerNameserver); len(u) > 0 {
		return u
	}
	for pattern, raw := range doc.DNS.NameserverPolicy {
		var list []any
		switch v := raw.(type) {
		case []any:
			list = v
		case string:
			list = []any{v}
		default:
			continue
		}
		https := httpsOnly(list)
		if len(https) == 0 {
			continue
		}
		if policyMatchesAny(pattern, nodeServers) {
			return https
		}
	}
	if u := httpsOnly(doc.DNS.Nameserver); len(u) > 0 {
		return u
	}
	panic(fmt.Sprintf("no https DoH/PSN in subscription dns for servers %v", nodeServers))
}

func policyMatchesAny(pattern string, hosts []string) bool {
	p := strings.TrimSpace(pattern)
	if strings.HasPrefix(p, "geosite:") || strings.HasPrefix(p, "geoip:") || strings.HasPrefix(p, "rule-set:") {
		return false
	}
	for _, h := range hosts {
		h = strings.ToLower(h)
		switch {
		case strings.HasPrefix(p, "*."):
			suf := strings.ToLower(p[1:])
			if strings.HasSuffix(h, suf) || h == strings.TrimPrefix(suf, ".") {
				return true
			}
		case strings.HasPrefix(p, "+."):
			suf := strings.ToLower(p[1:])
			if h == strings.TrimPrefix(suf, ".") || strings.HasSuffix(h, suf) {
				return true
			}
		default:
			if strings.EqualFold(h, p) {
				return true
			}
		}
	}
	return false
}

func samePassword(pwds []string, label string) string {
	if len(pwds) == 0 {
		panic(label + ": no usable nodes (empty or unparsed subscription file?); cannot derive the protocol key")
	}
	for _, p := range pwds[1:] {
		if p != pwds[0] {
			panic(label + ": node passwords differ; refuse shared upstream key (use per-node keys)")
		}
	}
	return pwds[0]
}

// The five app tabs. The first four take only their own country; 其他 takes
// every other country.
var regionMain = []string{"香港", "日本", "台湾", "新加坡", "其他"}

const otherRegion = "其他"

var regionPrimary = map[string]bool{
	"香港": true, "日本": true, "台湾": true, "新加坡": true,
}

var protoOf = map[string]store.Protocol{"anytls": store.ProtoAnyTLS, "trojan": store.ProtoTrojan}

// sourceNodes is one source after filtering: proxies per country, regular and
// residential, plus the first-seen country order.
type sourceNodes struct {
	src           *Source
	proto         store.Protocol
	doc           subDoc
	by, resBy     map[string][]map[string]any
	order         []string
	pwds, servers []string
}

func genNodes(in *Input) (*store.Catalog, string) {
	regions, profiles := buildCatalog(in)
	if len(endpoints) > 255 {
		panic(fmt.Sprintf("too many endpoints: %d (EpID is uint8, max 255)", len(endpoints)))
	}
	for _, r := range regions {
		if len(r.opts) > 255 {
			panic(fmt.Sprintf("region %s: too many NodeOpts: %d (Opt is uint8, max 255)", r.name, len(r.opts)))
		}
	}
	c := &store.Catalog{Version: store.SchemaVersion, Endpoints: endpoints, Profiles: profiles}
	for _, a := range regions {
		c.Regions = append(c.Regions, regionOut(a))
	}
	return c, fmt.Sprintf("%d regions, %d endpoints, %d profiles", len(regions), len(endpoints), len(profiles))
}

func readSource(in *Input, src *Source) *sourceNodes {
	sn := &sourceNodes{src: src, proto: protoOf[src.Proto], doc: readSub(src.Sub),
		by: map[string][]map[string]any{}, resBy: map[string][]map[string]any{}}
	var re *regexp.Regexp
	if src.RegionRegex != "" {
		re = regexp.MustCompile(src.RegionRegex)
	}
	seen := map[string]bool{}
	for _, m := range sn.doc.Proxies {
		if !typeAccepted(str(m, "type"), src.Types) {
			continue
		}
		raw := str(m, "name")
		if src.NamePrefix != "" && !strings.HasPrefix(raw, src.NamePrefix) {
			continue
		}
		name := cleanName(raw, src)
		if name == "" {
			continue
		}
		var country string
		if re != nil {
			mt := re.FindStringSubmatch(name)
			if len(mt) < 2 {
				panic(fmt.Sprintf("%s: name %q does not match region_regex", src.ID, raw))
			}
			country = mt[1]
			if v, ok := in.Aliases[country]; ok {
				country = v
			}
		} else {
			// "德国住宅 01" is a 德国 node: the marker is not part of the country.
			country = regionOf(stripMarker(name, src.ResidentialMatch), in.Aliases)
		}
		if !regionPrimary[country] {
			mustNotMentionMain(name, src.ID, in.Aliases)
		}
		if src.ResidentialMatch != "" && strings.Contains(name, src.ResidentialMatch) {
			sn.resBy[country] = append(sn.resBy[country], m)
		} else {
			sn.by[country] = append(sn.by[country], m)
		}
		rememberCountry(&sn.order, seen, country)
		sn.pwds = append(sn.pwds, str(m, "password"))
		sn.servers = append(sn.servers, str(m, "server"))
	}
	return sn
}

func stripMarker(name, marker string) string {
	if marker == "" {
		return name
	}
	return strings.Replace(name, marker, " ", 1)
}

func typeAccepted(typ string, types []string) bool {
	for _, t := range types {
		if strings.EqualFold(strings.TrimSpace(typ), t) {
			return true
		}
	}
	return false
}

// cleanName optionally starts the name at its first Han character and cuts it
// at a marker, so source-specific prefixes and tags do not reach the app.
func cleanName(s string, src *Source) string {
	if src.CleanFromFirstHan {
		for i, r := range s {
			if r >= 0x4E00 && r <= 0x9FA5 {
				s = s[i:]
				break
			}
		}
	}
	if src.CleanCutAt != "" {
		if j := strings.Index(s, src.CleanCutAt); j >= 0 {
			s = s[:j]
		}
	}
	if src.CleanFromFirstHan || src.CleanCutAt != "" {
		s = strings.TrimSpace(s)
	}
	return s
}

func buildCatalog(in *Input) ([]regionEmit, []store.UpstreamProfile) {
	var srcs []*sourceNodes
	var profiles []store.UpstreamProfile
	for i := range in.Sources {
		sn := readSource(in, &in.Sources[i])
		pwd := samePassword(sn.pwds, sn.src.ID)
		var key []byte
		switch sn.proto {
		case store.ProtoAnyTLS:
			sum := sha256.Sum256([]byte(pwd))
			key = sum[:]
		case store.ProtoTrojan:
			sum := sha256.Sum224([]byte(pwd))
			key = []byte(hex.EncodeToString(sum[:]))
		}
		profiles = append(profiles, store.UpstreamProfile{Proto: sn.proto, DoHUrls: dohForServers(sn.doc, sn.servers), Key: key})
		srcs = append(srcs, sn)
	}

	out := make([]regionEmit, 0, len(regionMain))
	for _, region := range regionMain {
		if region == otherRegion {
			continue
		}
		a := regionEmit{name: region}
		if appendCountryNodes(&a, region, srcs, in) == 0 {
			panic(region + ": no nodes in any source")
		}
		out = append(out, a)
	}
	other := regionEmit{name: otherRegion}
	nOther := 0
	for _, country := range otherCountryOrder(in.OtherFirst, srcs) {
		nOther += appendCountryNodes(&other, country, srcs, in)
	}
	if nOther == 0 {
		panic(otherRegion + ": no nodes in any source")
	}
	return append(out, other), profiles
}

func rememberCountry(order *[]string, seen map[string]bool, country string) {
	if country == "" || seen[country] {
		return
	}
	seen[country] = true
	*order = append(*order, country)
}

// otherCountryOrder puts other_first countries first, then each source's
// countries in source order and first appearance.
func otherCountryOrder(first []string, srcs []*sourceNodes) []string {
	seen := map[string]bool{}
	var out []string
	has := func(c string) bool {
		for _, s := range srcs {
			if len(s.by[c])+len(s.resBy[c]) > 0 {
				return true
			}
		}
		return false
	}
	add := func(c string) {
		if c == "" || regionPrimary[c] || seen[c] || !has(c) {
			return
		}
		seen[c] = true
		out = append(out, c)
	}
	for _, c := range first {
		add(c)
	}
	for _, s := range srcs {
		for _, c := range s.order {
			add(c)
		}
	}
	return out
}

// appendCountryNodes adds one country's nodes: regular nodes of every source
// (source order, shared numbering), then residential ones (own numbering).
func appendCountryNodes(a *regionEmit, country string, srcs []*sourceNodes, in *Input) int {
	seq, resSeq := 0, 0
	for _, s := range srcs {
		for _, m := range s.by[country] {
			seq++
			a.nodes = append(a.nodes, nodeFrom(a, m, nodeName(in.Naming.Regular, country, seq), s.proto, in))
		}
	}
	for _, s := range srcs {
		for _, m := range s.resBy[country] {
			resSeq++
			a.nodes = append(a.nodes, nodeFrom(a, m, nodeName(in.Naming.Residential, country, resSeq), s.proto, in))
		}
	}
	return seq + resSeq
}

func nodeName(tmpl, country string, n int) string {
	s := strings.ReplaceAll(tmpl, "{country}", country)
	s = strings.ReplaceAll(s, "{n:02}", fmt.Sprintf("%02d", n))
	return strings.ReplaceAll(s, "{n}", strconv.Itoa(n))
}

func dohForServers(doc subDoc, servers []string) []string {
	if len(servers) == 0 {
		panic("no servers for DoH/PSN binding")
	}
	return dohFromSub(doc, servers)
}

func regionOf(name string, aliases map[string]string) string {
	best, canon := "", ""
	try := func(key, c string) {
		if strings.HasPrefix(name, key) && len(key) > len(best) {
			best, canon = key, c
		}
	}
	for r := range regionPrimary {
		try(r, r)
	}
	for k, v := range aliases {
		try(k, v)
	}
	if canon != "" {
		return canon
	}
	if f := strings.Fields(name); len(f) > 0 {
		return f[0]
	}
	return name
}

func mustNotMentionMain(name, src string, aliases map[string]string) {
	for r := range regionPrimary {
		if strings.Contains(name, r) {
			panic(fmt.Sprintf("%s: node %q mentions %s but was not assigned to it; fix the region rules", src, name, r))
		}
	}
	for k, v := range aliases {
		if regionPrimary[v] && strings.Contains(name, k) {
			panic(fmt.Sprintf("%s: node %q mentions %s but was not assigned to it; fix the region rules", src, name, k))
		}
	}
}

func optsEqual(a, b nodeOpts) bool {
	return a.fp == b.fp && a.skip == b.skip && a.udp == b.udp &&
		strings.Join(a.alpn, ",") == strings.Join(b.alpn, ",") && (a.alpn == nil) == (b.alpn == nil) &&
		a.idleCheck == b.idleCheck && a.idleTO == b.idleTO &&
		a.minIdle == b.minIdle && a.minIdleSet == b.minIdleSet &&
		a.padding == b.padding && a.metadata == b.metadata
}

func intOrDurationSec(m map[string]any, k string) (int, bool) {
	v, ok := m[k]
	if !ok || v == nil {
		return 0, false
	}
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case uint64:
		return int(x), true
	case float64:
		return int(x), true
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0, false
		}
		if d, err := time.ParseDuration(s); err == nil {
			sec := int(d / time.Second)
			if sec == 0 && d > 0 {
				sec = 1
			}
			return sec, true
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(x)))
		if err != nil {
			return 0, false
		}
		return n, true
	}
}

// sessionOpt reads one AnyTLS session option. A key that is present must parse
// and be at least min; codegen stops otherwise, so a misconfigured value never
// ships and is never silently replaced at run time.
func sessionOpt(m map[string]any, name, k string, min int) (int, bool) {
	if v, ok := m[k]; !ok || v == nil {
		return 0, false
	}
	v, ok := intOrDurationSec(m, k)
	if !ok || v < min {
		panic(fmt.Sprintf("%s: invalid %s %v (want an integer or duration >= %d)", name, k, m[k], min))
	}
	return v, true
}

// nodeOptsFrom reads the TLS and AnyTLS session options. padKey / metaKey name
// the YAML keys carrying the padding scheme and client metadata ("" = none).
func nodeOptsFrom(m map[string]any, name, padKey, metaKey string) nodeOpts {
	o := nodeOpts{
		fp:   strings.ToLower(str(m, "client-fingerprint")),
		alpn: strList(m, "alpn"),
		skip: boolean(m, "skip-cert-verify"),
		udp:  boolean(m, "udp"),
	}
	if padKey != "" {
		o.padding = str(m, padKey)
	}
	if metaKey != "" {
		o.metadata = str(m, metaKey)
	}
	if v, ok := sessionOpt(m, name, "idle-session-check-interval", 1); ok {
		o.idleCheck = v
	}
	if v, ok := sessionOpt(m, name, "idle-session-timeout", 1); ok {
		o.idleTO = v
	}
	if v, ok := sessionOpt(m, name, "min-idle-session", 0); ok {
		o.minIdle, o.minIdleSet = v, true
	}
	return o
}

// requirePlainTransport stops codegen on transports or TLS extensions the
// core does not implement, so such a node never ships as a dead entry.
func requirePlainTransport(m map[string]any, name string) {
	switch strings.ToLower(strings.TrimSpace(str(m, "network"))) {
	case "", "tcp":
	default:
		panic(fmt.Sprintf("%s: unsupported network %q", name, str(m, "network")))
	}
	for _, k := range []string{"reality-opts", "ech-opts", "fingerprint", "certificate", "private-key"} {
		if v, ok := m[k]; ok && v != nil && fmt.Sprint(v) != "" {
			panic(fmt.Sprintf("%s: unsupported option %s", name, k))
		}
	}
	if ss, ok := m["ss-opts"].(map[string]any); ok && boolean(ss, "enabled") {
		panic(fmt.Sprintf("%s: unsupported option ss-opts", name))
	}
}

func nodeFrom(a *regionEmit, m map[string]any, name string, proto store.Protocol, in *Input) node {
	port, _ := strconv.Atoi(str(m, "port"))
	requirePlainTransport(m, name)
	o := nodeOptsFrom(m, name, in.YAMLKeys.Padding, in.YAMLKeys.Metadata)
	idx := -1
	for i, x := range a.opts {
		if optsEqual(x, o) {
			idx = i
			break
		}
	}
	if idx < 0 {
		idx, a.opts = len(a.opts), append(a.opts, o)
	}
	sni := str(m, "sni")
	if sni == "" {
		sni = str(m, "server")
	}
	return node{name: name, proto: proto, sni: sni, ep: endpoint(str(m, "server"), proto), port: port, opt: idx}
}

func regionOut(a regionEmit) store.Region {
	r := store.Region{Name: a.name}
	sni := ""
	if len(a.nodes) > 0 {
		sni = a.nodes[0].sni
		for _, n := range a.nodes {
			if n.sni != sni {
				sni = ""
				break
			}
		}
	}
	r.SNI = sni
	for _, o := range a.opts {
		r.Opts = append(r.Opts, store.NodeOpts{
			Fingerprint:                 o.fp,
			ALPN:                        o.alpn,
			SkipCertVerify:              o.skip,
			UDP:                         o.udp,
			IdleSessionCheckIntervalSec: o.idleCheck,
			IdleSessionTimeoutSec:       o.idleTO,
			MinIdleSession:              o.minIdle,
			MinIdleSessionSet:           o.minIdleSet,
			PaddingScheme:               o.padding,
			ClientMetadata:              o.metadata,
		})
	}
	for _, n := range a.nodes {
		nd := store.Node{Name: n.name, Proto: n.proto, EpID: uint8(n.ep), Port: uint16(n.port), Opt: uint8(n.opt)}
		if sni == "" {
			nd.SNI = n.sni
		}
		r.Nodes = append(r.Nodes, nd)
	}
	return r
}
