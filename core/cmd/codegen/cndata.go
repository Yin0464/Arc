package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func writeCNData(dir string) {

	geo := readLines(filepath.Join(rawDir, "geoip_cn.txt"))

	op4 := readLines(filepath.Join(rawDir, "operator_china.txt"))
	op6 := readLines(filepath.Join(rawDir, "operator_china6.txt"))
	floor(len(op4), 3000, "china-operator-ip v4")
	floor(len(op6), 1000, "china-operator-ip v6")
	c4, c6 := parseRanges(append(append(geo, op4...), op6...))
	floor(len(c4), 1000, "geoip CN v4")
	floor(len(c6), 1000, "geoip CN v6")
	g4, g6 := parseRanges(readLines(filepath.Join(rawDir, "geoip_google.txt")))
	floor(len(g4), 100, "geoip google v4")
	floor(len(g6), 10, "geoip google v6")
	s4 := segments(c4, g4)
	s6 := segments(c6, g6)
	writeSeg4(filepath.Join(dir, "ip4.bin"), s4)
	writeSeg6(filepath.Join(dir, "ip6.bin"), s6)
	foreign, cn := fusedDomainLists()
	writeDomTable(filepath.Join(dir, "dom.bin"), cn, foreign)
	fmt.Fprintf(os.Stderr, "tables: ip4 cn %d + google %d ranges -> %d segments; ip6 cn %d + google %d -> %d; domains foreign %d + cn %d\n",
		len(c4), len(g4), len(s4), len(c6), len(g6), len(s6), len(foreign), len(cn))
}

const (
	tagNone    = 0
	tagCN      = 1
	tagForeign = 2
	tagGoogle  = tagForeign
)

type r64 struct{ s, e uint64 }

type seg struct {
	start uint64
	tag   byte
}

func parseRanges(lines []string) (v4, v6 []r64) {
	for _, l := range lines {
		p, err := netip.ParsePrefix(strings.TrimSpace(l))
		if err != nil {
			continue
		}
		p = p.Masked()
		if p.Addr().Is4() {
			b := p.Addr().As4()
			st := uint64(binary.BigEndian.Uint32(b[:]))
			v4 = append(v4, r64{st, st | (uint64(1)<<(32-p.Bits()) - 1)})
			continue
		}
		b := p.Addr().As16()
		st := binary.BigEndian.Uint64(b[:8])
		v6 = append(v6, r64{st, st | (^uint64(0) >> min(p.Bits(), 64))})
	}
	return merge64(v4), merge64(v6)
}

func merge64(in []r64) []r64 {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(a, b int) bool { return in[a].s < in[b].s })
	out := []r64{in[0]}
	for _, r := range in[1:] {
		if l := &out[len(out)-1]; r.s <= l.e || (l.e != ^uint64(0) && r.s == l.e+1) {
			l.e = max(l.e, r.e)
		} else {
			out = append(out, r)
		}
	}
	return out
}

func covers(rs []r64, x uint64) bool {
	i := sort.Search(len(rs), func(i int) bool { return rs[i].e >= x })
	return i < len(rs) && rs[i].s <= x
}

func segments(cn, goog []r64) []seg {
	cuts := []uint64{0}
	for _, rs := range [][]r64{cn, goog} {
		for _, r := range rs {
			cuts = append(cuts, r.s)
			if r.e != ^uint64(0) {
				cuts = append(cuts, r.e+1)
			}
		}
	}
	sort.Slice(cuts, func(a, b int) bool { return cuts[a] < cuts[b] })
	var out []seg
	for i, c := range cuts {
		if i > 0 && c == cuts[i-1] {
			continue
		}
		t := byte(tagNone)
		if covers(goog, c) {
			t = tagGoogle
		} else if covers(cn, c) {
			t = tagCN
		}
		if len(out) == 0 || out[len(out)-1].tag != t {
			out = append(out, seg{c, t})
		}
	}
	return out
}

func appendTags(buf []byte, ss []seg) []byte {
	tags := make([]byte, (len(ss)+3)/4)
	for i, s := range ss {
		tags[i/4] |= s.tag << (2 * (i % 4))
	}
	return append(buf, tags...)
}

func writeSeg4(file string, ss []seg) {
	if len(ss) > 65535 {
		panic("too many IPv4 segments for the uint16 index")
	}
	buf := binary.LittleEndian.AppendUint32(nil, uint32(len(ss)))
	j := 0
	for h := 0; h <= 4096; h++ {
		for j < len(ss) && ss[j].start < uint64(h)<<20 {
			j++
		}
		buf = binary.LittleEndian.AppendUint16(buf, uint16(j))
	}
	for _, s := range ss {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(s.start))
	}
	check(os.WriteFile(file, appendTags(buf, ss), 0o644))
}

func writeSeg6(file string, ss []seg) {
	buf := binary.LittleEndian.AppendUint32(nil, uint32(len(ss)))
	for _, s := range ss {
		buf = binary.LittleEndian.AppendUint64(buf, s.start)
	}
	check(os.WriteFile(file, appendTags(buf, ss), 0o644))
}

func writeDomTable(file string, cn, foreign []string) {
	writeDomDAT(file, cn, foreign)
}

type datNode struct {
	child map[string]*datNode
	tag   uint8
	kids  []string
}

func datSetTag(old, kind, tag uint8) uint8 {
	if kind == 0 {
		if old&3 == tagForeign && tag != tagForeign {
			return old
		}
		return (old &^ 3) | tag
	}
	if (old>>2)&3 == tagForeign && tag != tagForeign {
		return old
	}
	return (old &^ 0xc) | (tag << 2)
}

func writeDomDAT(file string, cn, foreign []string) {
	root := &datNode{child: map[string]*datNode{}}
	insert := func(d string, tag uint8) {
		exact := false
		if strings.HasPrefix(d, exactPrefix) {
			exact = true
			d = d[len(exactPrefix):]
		}
		if d == "" {
			return
		}
		cur := root
		labs := strings.Split(d, ".")
		for i := len(labs) - 1; i >= 0; i-- {
			lab := labs[i]
			if lab == "" {
				continue
			}
			n := cur.child[lab]
			if n == nil {
				n = &datNode{child: map[string]*datNode{}}
				cur.child[lab] = n
			}
			cur = n
		}
		if exact {
			cur.tag = datSetTag(cur.tag, 1, tag)
		} else {
			cur.tag = datSetTag(cur.tag, 0, tag)
		}
	}
	for _, d := range foreign {
		insert(d, tagForeign)
	}
	dup := 0
	foreignName := make(map[string]bool, len(foreign))
	for _, d := range foreign {
		foreignName[d] = true
	}
	for _, d := range cn {
		if foreignName[d] {
			dup++
			continue
		}
		insert(d, tagCN)
	}

	const maxHolePct = 5.0
	var best []byte
	var bestMeta string
	okBuild := false
	for attempt := 0; attempt < 4; attempt++ {
		raw, meta, holePct, err := buildDomDAT(root, attempt)
		if err != nil {
			panic(err)
		}
		best, bestMeta = raw, meta
		if holePct <= maxHolePct {
			okBuild = true
			break
		}
		fmt.Fprintf(os.Stderr, "dom DAT attempt %d hole %.3f%% > %.1f%%, densify retry\n", attempt, holePct, maxHolePct)
	}
	if !okBuild {
		panic(fmt.Sprintf("dom DAT hole rate exceeds %.1f%% after retries: %s", maxHolePct, bestMeta))
	}

	body := best
	out := make([]byte, 0, 12+len(body))
	out = append(out, 'D', 'A', 'T', '3')
	out = binary.LittleEndian.AppendUint32(out, 0) // flags: raw body
	out = binary.LittleEndian.AppendUint32(out, uint32(len(body)))
	out = append(out, body...)
	check(os.WriteFile(file, out, 0o644))
	fmt.Fprintf(os.Stderr, "dom DAT3: %s; file %d bytes; foreign %d cn %d (-%d same-name)\n",
		bestMeta, len(out), len(foreign), len(cn)-dup, dup)
}

func buildDomDAT(root *datNode, attempt int) (raw []byte, meta string, holePct float64, err error) {
	type item struct {
		n *datNode
		f int
	}
	var nodes []*datNode
	var collect func(*datNode)
	collect = func(n *datNode) {
		nodes = append(nodes, n)
		n.kids = n.kids[:0]
		for lab := range n.child {
			n.kids = append(n.kids, lab)
		}
		sort.Strings(n.kids)
		for _, lab := range n.kids {
			collect(n.child[lab])
		}
	}
	collect(root)

	items := make([]item, 0, len(nodes))
	for _, n := range nodes {
		if len(n.kids) > 0 {
			items = append(items, item{n, len(n.kids)})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].f != items[j].f {
			return items[i].f > items[j].f
		}
		if attempt%2 == 1 {
			return items[i].n.kids[0] > items[j].n.kids[0]
		}
		return items[i].n.kids[0] < items[j].n.kids[0]
	})

	labelCode := map[string]int{}
	labels := make([]string, 0, 128)
	nextCode := 1
	assignFresh := func(labs []string) {
		var fresh []string
		for _, lab := range labs {
			if labelCode[lab] == 0 {
				fresh = append(fresh, lab)
			}
		}
		if attempt >= 2 {
			sort.Strings(fresh)
			if attempt == 3 {
				for i, j := 0, len(fresh)-1; i < j; i, j = i+1, j-1 {
					fresh[i], fresh[j] = fresh[j], fresh[i]
				}
			}
		}
		for _, lab := range fresh {
			labelCode[lab] = nextCode
			nextCode++
			labels = append(labels, lab)
		}
	}
	for _, it := range items {
		assignFresh(it.n.kids)
	}
	for _, n := range nodes {
		sort.Slice(n.kids, func(i, j int) bool { return labelCode[n.kids[i]] < labelCode[n.kids[j]] })
	}

	slotCap := len(nodes) + 2
	base := make([]int32, slotCap)
	labArr := make([]uint32, slotCap)
	info := make([]uint32, slotCap) // low4=tag, rest=fan
	used := make([]bool, slotCap)
	used[0] = true
	ensure := func(i int) {
		for i >= len(base) {
			n := len(base) * 2
			if n <= i {
				n = i + 1
			}
			base = append(base, make([]int32, n-len(base))...)
			labArr = append(labArr, make([]uint32, n-len(labArr))...)
			info = append(info, make([]uint32, n-len(info))...)
			used = append(used, make([]bool, n-len(used))...)
		}
	}
	ensure(1)
	used[1] = true
	stateOf := map[*datNode]int{root: 1}
	nextFree := 2

	findBase := func(k int) int {
		if k == 0 {
			return 0
		}
		for {
			ensure(nextFree + k)
			ok := true
			start := nextFree
			for j := 0; j < k; j++ {
				if used[start+j] {
					ok = false
					nextFree = start + j + 1
					break
				}
			}
			if ok {
				return start - 1
			}
		}
	}

	q := newMaxQueue(len(nodes))
	q.push(root)
	for q.len() > 0 {
		n := q.popFirstMax()
		s := stateOf[n]
		k := len(n.kids)
		if k == 0 {
			base[s] = 0
			info[s] = uint32(n.tag)
			continue
		}
		b := findBase(k)
		base[s] = int32(b)
		info[s] = uint32(n.tag) | (uint32(k) << 4)
		for i, name := range n.kids {
			t := b + 1 + i
			ensure(t)
			used[t] = true
			labArr[t] = uint32(labelCode[name])
			ch := n.child[name]
			stateOf[ch] = t
			q.push(ch)
		}
		nextFree = b + 1 + k
	}

	size := nextFree
	for size > 2 && !used[size-1] {
		size--
	}
	holes, usedN := 0, 0
	for i := 1; i < size; i++ {
		if used[i] {
			usedN++
		} else {
			holes++
		}
	}
	holePct = 100 * float64(holes) / float64(size-1)

	var labBlob bytes.Buffer
	for _, lab := range labels {
		if len(lab) > 255 {
			return nil, "", 0, fmt.Errorf("label too long %d", len(lab))
		}
		labBlob.WriteByte(byte(len(lab)))
		labBlob.WriteString(lab)
	}

	buf := bytes.NewBuffer(make([]byte, 0, 16+labBlob.Len()+size*12))
	binary.Write(buf, binary.LittleEndian, uint32(len(labels)))
	binary.Write(buf, binary.LittleEndian, uint32(size))
	binary.Write(buf, binary.LittleEndian, uint32(1))
	buf.Write(labBlob.Bytes())
	for i := 0; i < size; i++ {
		binary.Write(buf, binary.LittleEndian, base[i])
	}
	for i := 0; i < size; i++ {
		binary.Write(buf, binary.LittleEndian, labArr[i])
	}
	for i := 0; i < size; i++ {
		binary.Write(buf, binary.LittleEndian, info[i])
	}

	meta = fmt.Sprintf("labels %d nodes %d slots %d used %d holes %d hole %.3f%% rawBody %d",
		len(labels), usedN, size-1, usedN, holes, holePct, buf.Len())
	return buf.Bytes(), meta, holePct, nil
}

const exactPrefix = "="

var skippedRules = map[string]int{}

func logSkipped(list string) {
	for k, n := range skippedRules {
		if strings.HasPrefix(k, list+" ") {
			fmt.Fprintf(os.Stderr, "%s: %d %s rules not representable (suffix/exact table only), skipped\n", list, n, strings.TrimPrefix(k, list+" "))
		}
	}
}

func expandV2fly(root string, cnOnly bool) map[string]bool {
	set := map[string]bool{}
	seen := map[string]bool{}
	var walk func(name string, keep, drop []string)
	walk = func(name string, keep, drop []string) {
		key := name + "|" + strings.Join(keep, ",") + "|" + strings.Join(drop, ",")
		if seen[key] {
			return
		}
		seen[key] = true
		for _, l := range readLines(filepath.Join(rawDir, "v2fly_"+name)) {
			if i := strings.IndexByte(l, '#'); i >= 0 {
				l = l[:i]
			}
			f := strings.Fields(l)
			if len(f) == 0 {
				continue
			}
			e := f[0]
			attrs := map[string]bool{}
			var ik, id []string
			for _, a := range f[1:] {
				switch {
				case strings.HasPrefix(a, "@-"):
					id = append(id, a[2:])
				case strings.HasPrefix(a, "@"):
					attrs[a[1:]] = true
					ik = append(ik, a[1:])
				}
			}
			if strings.HasPrefix(e, "include:") {
				walk(strings.TrimPrefix(e, "include:"), ik, id)
				continue
			}
			if cnOnly && attrs["!cn"] {
				continue
			}
			ok := true
			for _, k := range keep {
				ok = ok && attrs[k]
			}
			for _, k := range drop {
				ok = ok && !attrs[k]
			}
			if !ok {
				continue
			}
			switch {
			case strings.HasPrefix(e, "domain:"):
				set[strings.ToLower(e[len("domain:"):])] = true
			case strings.HasPrefix(e, "full:"):
				set[exactPrefix+strings.ToLower(e[len("full:"):])] = true
			case strings.HasPrefix(e, "keyword:"), strings.HasPrefix(e, "regexp:"):
				skippedRules[root+" "+e[:strings.IndexByte(e, ':')]]++
			case !strings.Contains(e, ":"):
				set[strings.ToLower(e)] = true
			}
		}
	}
	walk(root, nil, nil)
	return set
}

func fusedDomainLists() (foreign, cn []string) {
	goog := GoogleDomains()
	noAtCN, atCN := geolocationNotCN()
	china := ChinaDomains()

	foreignSet := map[string]bool{}
	for _, d := range goog {
		foreignSet[d] = true
	}
	t2add, t2skip := 0, 0
	for _, d := range noAtCN {
		if foreignSet[d] {
			t2skip++
			continue
		}
		foreignSet[d] = true
		t2add++
	}
	foreign = dedupe(foreignSet)

	cnSet := map[string]bool{}
	t3add, t3skip := 0, 0
	for _, d := range atCN {
		if foreignSet[d] {
			t3skip++
			continue
		}
		cnSet[d] = true
		t3add++
	}
	t4add, t4skip := 0, 0
	for _, d := range china {
		if foreignSet[d] {
			t4skip++
			continue
		}
		if cnSet[d] {
			continue
		}
		cnSet[d] = true
		t4add++
	}
	cn = dedupe(cnSet)
	fmt.Fprintf(os.Stderr, "dom tiers: google %d; !cn-no-@cn %d (+%d / -%d already-foreign); !cn-@cn %d (+%d cn / -%d foreign); china %d (+%d cn / -%d foreign); fused foreign %d cn %d\n",
		len(goog), len(noAtCN), t2add, t2skip, len(atCN), t3add, t3skip, len(china), t4add, t4skip, len(foreign), len(cn))
	return foreign, cn
}

func geolocationNotCN() (noAtCN, atCN []string) {
	path := filepath.Join(rawDir, "v2fly_geolocation-!cn.txt")
	lines := readLines(path)
	floor(len(lines), 1000, "v2fly geolocation-!cn flat list")
	noSet, atSet := map[string]bool{}, map[string]bool{}
	for _, l := range lines {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		var kind, rest string
		switch {
		case strings.HasPrefix(l, "domain:"):
			kind, rest = "domain", l[len("domain:"):]
		case strings.HasPrefix(l, "full:"):
			kind, rest = "full", l[len("full:"):]
		case strings.HasPrefix(l, "keyword:"), strings.HasPrefix(l, "regexp:"):
			typ := l[:strings.IndexByte(l, ':')]
			skippedRules["geolocation-!cn "+typ]++
			continue
		default:
			continue
		}
		host := rest
		hasCN := false
		if i := strings.Index(rest, ":@"); i >= 0 {
			host = rest[:i]
			for _, a := range strings.Split(rest[i+2:], ",") {
				a = strings.TrimSpace(strings.TrimPrefix(a, "@"))
				if a == "cn" {
					hasCN = true
				}
			}
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if kind == "full" {
			host = exactPrefix + host
		}
		if hasCN {
			atSet[host] = true
		} else {
			noSet[host] = true
		}
	}
	logSkipped("geolocation-!cn")
	noAtCN, atCN = dedupe(noSet), dedupe(atSet)
	fmt.Fprintf(os.Stderr, "geolocation-!cn: no-@cn %d, @cn %d (after parent dedupe)\n", len(noAtCN), len(atCN))
	return noAtCN, atCN
}

func GoogleDomains() []string {
	set := expandV2fly("google", false)
	logSkipped("google")
	floor(len(set), 300, "v2fly google list")
	ls := geositeCategory(filepath.Join(rawDir, "loyalsoldier_geosite.dat"), "GOOGLE")
	logSkipped("geosite:GOOGLE")
	floor(len(ls), 300, "Loyalsoldier geosite google")
	added := 0
	for _, d := range ls {
		if !set[d] {
			set[d] = true
			added++
		}
	}
	fmt.Fprintf(os.Stderr, "google domains: v2fly %d, +%d from Loyalsoldier geosite google (%d)\n", len(set)-added, added, len(ls))
	return dedupe(set)
}

func ChinaDomains() []string {
	set := map[string]bool{}
	for _, f := range []string{"accelerated-domains.china.conf"} {
		for _, l := range readLines(filepath.Join(rawDir, f)) {
			if p := strings.Split(strings.TrimSpace(l), "/"); len(p) >= 3 && p[0] == "server=" {
				if d := strings.Trim(strings.ToLower(p[1]), "."); d != "" {
					set[d] = true
				}
			}
		}
	}
	floor(len(set), 50000, "china domain list")

	geo := expandV2fly("geolocation-cn", true)
	logSkipped("geolocation-cn")
	floor(len(geo), 3000, "v2fly geolocation-cn list")
	added := 0
	for d := range geo {
		if !set[d] {
			set[d] = true
			added++
		}
	}
	fmt.Fprintf(os.Stderr, "cn domains: +%d from v2fly geolocation-cn (%d entries)\n", added, len(geo))
	out := dedupe(set)
	fmt.Fprintf(os.Stderr, "cn domains: %d listed, %d after parent dedupe\n", len(set), len(out))
	return out
}

func dedupe(set map[string]bool) []string {
	var out []string
outer:
	for d := range set {
		if strings.HasPrefix(d, exactPrefix) && set[d[len(exactPrefix):]] {
			continue
		}
		for i := 0; i < len(d); i++ {
			if d[i] == '.' && set[d[i+1:]] {
				continue outer
			}
		}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func geositeCategory(local, code string) []string {
	data, err := os.ReadFile(local)
	check(err)
	var out []string
	for _, site := range pbFields(data, 1) {
		cc := pbFields(site, 1)
		if len(cc) != 1 || !strings.EqualFold(string(cc[0]), code) {
			continue
		}
		for _, dm := range pbFields(site, 2) {
			typ, val := pbVarint(dm, 1), pbFields(dm, 2)
			switch {
			case len(val) != 1:
			case typ == 2:
				out = append(out, strings.ToLower(string(val[0])))
			case typ == 3:
				out = append(out, exactPrefix+strings.ToLower(string(val[0])))
			default:
				skippedRules["geosite:"+code+" type"+strconv.Itoa(int(typ))]++
			}
		}
	}
	return out
}

func pbNext(b []byte) (field, wt int, val []byte, n uint64, rest []byte, ok bool) {
	k, i := binary.Uvarint(b)
	if i <= 0 {
		return
	}
	b = b[i:]
	field, wt = int(k>>3), int(k&7)
	switch wt {
	case 0:
		v, j := binary.Uvarint(b)
		if j <= 0 {
			return
		}
		return field, wt, nil, v, b[j:], true
	case 2:
		l, j := binary.Uvarint(b)
		if j <= 0 || uint64(len(b)-j) < l {
			return
		}
		return field, wt, b[j : j+int(l)], 0, b[j+int(l):], true
	case 1:
		if len(b) < 8 {
			return
		}
		return field, wt, nil, 0, b[8:], true
	case 5:
		if len(b) < 4 {
			return
		}
		return field, wt, nil, 0, b[4:], true
	}
	return
}

func pbFields(b []byte, want int) (out [][]byte) {
	for len(b) > 0 {
		f, wt, v, _, rest, ok := pbNext(b)
		if !ok {
			return
		}
		if f == want && wt == 2 {
			out = append(out, v)
		}
		b = rest
	}
	return
}

func pbVarint(b []byte, want int) uint64 {
	for len(b) > 0 {
		f, wt, _, n, rest, ok := pbNext(b)
		if !ok {
			return 0
		}
		if f == want && wt == 0 {
			return n
		}
		b = rest
	}
	return 0
}

// maxQueue reproduces the old "first index with the most kids, then
// swap-remove" scan over a slice in O(log n) per operation, so the DAT layout
// stays byte-identical.
type maxQueue struct {
	items []*datNode
	tree  []int // index into items of the best leaf in each subtree, -1 empty
	size  int
}

func newMaxQueue(capacity int) *maxQueue {
	size := 1
	for size < capacity+1 {
		size <<= 1
	}
	t := make([]int, 2*size)
	for i := range t {
		t[i] = -1
	}
	return &maxQueue{items: make([]*datNode, 0, capacity), tree: t, size: size}
}

func (q *maxQueue) len() int { return len(q.items) }

func (q *maxQueue) better(a, b int) int {
	switch {
	case a < 0:
		return b
	case b < 0:
		return a
	case len(q.items[b].kids) > len(q.items[a].kids):
		return b
	case len(q.items[a].kids) > len(q.items[b].kids):
		return a
	case a < b:
		return a
	}
	return b
}

func (q *maxQueue) set(pos int, present bool) {
	i := pos + q.size
	if present {
		q.tree[i] = pos
	} else {
		q.tree[i] = -1
	}
	for i >>= 1; i > 0; i >>= 1 {
		q.tree[i] = q.better(q.tree[2*i], q.tree[2*i+1])
	}
}

func (q *maxQueue) push(n *datNode) {
	q.items = append(q.items, n)
	q.set(len(q.items)-1, true)
}

func (q *maxQueue) popFirstMax() *datNode {
	bi := q.tree[1]
	n := q.items[bi]
	last := len(q.items) - 1
	q.items[bi] = q.items[last]
	q.items = q.items[:last]
	q.set(last, false)
	if bi != last {
		q.set(bi, true)
	}
	return n
}
