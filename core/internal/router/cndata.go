package router

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"
)

// The tables are build products, not in git: build.sh generates them from
// freshly fetched upstream rule data (cmd/codegen); on a fresh clone
// `go run ./cmd/codegen -fixture` writes a tiny test set for offline tests.
var (
	//go:embed ip4.bin
	ip4Tab string
	//go:embed ip6.bin
	ip6Tab string
	//go:embed dom.bin
	domTab string
)

const (
	tagNone    = 0
	tagCN      = 1
	tagForeign = 2
	tagGoogle  = tagForeign
)

func u16(s string, i int) uint32 { return uint32(s[i]) | uint32(s[i+1])<<8 }
func u32(s string, i int) uint32 {
	return uint32(s[i]) | uint32(s[i+1])<<8 | uint32(s[i+2])<<16 | uint32(s[i+3])<<24
}
func u64(s string, i int) uint64 { return uint64(u32(s, i)) | uint64(u32(s, i+4))<<32 }

func segTag(tab string, tagOff, i int) int { return int(tab[tagOff+i/4]>>(2*(i%4))) & 3 }

var (
	ip4N   = int(u32(ip4Tab, 0))
	ip4St  = 4 + 4097*2
	ip4Tag = ip4St + ip4N*4
	ip6N   = int(u32(ip6Tab, 0))
	ip6Tag = 4 + ip6N*8
)

func ipTag4(ip uint32) int {
	h := int(ip >> 20)
	lo, hi := int(u16(ip4Tab, 4+h*2)), int(u16(ip4Tab, 4+(h+1)*2))
	if lo > 0 {
		lo--
	}
	for lo+1 < hi {
		m := int(uint(lo+hi) >> 1)
		if u32(ip4Tab, ip4St+m*4) <= ip {
			lo = m
		} else {
			hi = m
		}
	}
	return segTag(ip4Tab, ip4Tag, lo)
}

func ipTag6(hi64 uint64) int {
	lo, hi := 0, ip6N
	for lo+1 < hi {
		m := int(uint(lo+hi) >> 1)
		if u64(ip6Tab, 4+m*8) <= hi64 {
			lo = m
		} else {
			hi = m
		}
	}
	return segTag(ip6Tab, ip6Tag, lo)
}

var (
	domOnce     sync.Once
	domBase     []int32
	domLab      []uint32
	domInfo     []uint32
	domRoot     int32
	domLabBytes []byte    // packed label UTF-8
	domLabSlots []labSlot // open-addressing; empty when n==0
	domLoadErr  error
)

// labSlot is one open-addressing entry (empty ⟺ n==0).
type labSlot struct {
	hash uint32
	off  uint32
	n    uint16
	code uint32
}

func ensureDom() {
	// dom.bin is stored raw; parse it in place from the embedded read-only data.
	domOnce.Do(func() { domLoadErr = loadDomDAT(unsafe.Slice(unsafe.StringData(domTab), len(domTab))) })
	if domLoadErr != nil {
		panic(domLoadErr)
	}
}

func loadDomDAT(file []byte) error {
	if len(file) < 12 || string(file[:4]) != "DAT3" {
		return fmt.Errorf("dom.bin: bad magic")
	}
	flags := binary.LittleEndian.Uint32(file[4:])
	size := binary.LittleEndian.Uint32(file[8:])
	body := file[12:]
	if flags != 0 {
		return fmt.Errorf("dom.bin: unsupported flags %#x", flags)
	}
	if uint32(len(body)) != size {
		return fmt.Errorf("dom.bin: size %d want %d", len(body), size)
	}
	if len(body) < 12 {
		return fmt.Errorf("dom.bin: short body")
	}
	labelCount := int(binary.LittleEndian.Uint32(body[0:]))
	slotCount := int(binary.LittleEndian.Uint32(body[4:]))
	domRoot = int32(binary.LittleEndian.Uint32(body[8:]))
	off := 12
	if labelCount < 0 || slotCount < 2 {
		return fmt.Errorf("dom.bin: counts")
	}

	type labRaw struct {
		s    string
		code uint32
	}
	raws := make([]labRaw, 0, labelCount)
	for c := 1; c <= labelCount; c++ {
		if off >= len(body) {
			return fmt.Errorf("dom.bin: label %d hdr", c)
		}
		n := int(body[off])
		off++
		if off+n > len(body) {
			return fmt.Errorf("dom.bin: label %d bytes", c)
		}
		if n == 0 {
			return fmt.Errorf("dom.bin: empty label %d", c)
		}
		raws = append(raws, labRaw{s: string(body[off : off+n]), code: uint32(c)})
		off += n
	}
	total := 0
	for _, r := range raws {
		total += len(r.s)
	}
	blob := make([]byte, 0, total)
	type packed struct {
		off, n uint32
		code   uint32
		hash   uint32
	}
	pk := make([]packed, labelCount)
	for i, r := range raws {
		start := uint32(len(blob))
		blob = append(blob, r.s...)
		pk[i] = packed{off: start, n: uint32(len(r.s)), code: r.code, hash: labHash(r.s)}
	}
	domLabBytes = blob

	capSlots := 1
	for capSlots < labelCount*2 {
		capSlots <<= 1
	}
	slots := make([]labSlot, capSlots)
	mask := uint32(capSlots - 1)
	for _, e := range pk {
		i := e.hash & mask
		for slots[i].n != 0 {
			i = (i + 1) & mask
		}
		slots[i] = labSlot{hash: e.hash, off: e.off, n: uint16(e.n), code: e.code}
	}
	domLabSlots = slots

	need := slotCount * 4 * 3
	if off+need > len(body) {
		return fmt.Errorf("dom.bin: arrays short")
	}
	domBase = make([]int32, slotCount)
	domLab = make([]uint32, slotCount)
	domInfo = make([]uint32, slotCount)
	for i := 0; i < slotCount; i++ {
		domBase[i] = int32(binary.LittleEndian.Uint32(body[off:]))
		off += 4
	}
	for i := 0; i < slotCount; i++ {
		domLab[i] = binary.LittleEndian.Uint32(body[off:])
		off += 4
	}
	for i := 0; i < slotCount; i++ {
		domInfo[i] = binary.LittleEndian.Uint32(body[off:])
		off += 4
	}
	return nil
}

func labHash(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func labLookup(s string) uint32 {
	slots := domLabSlots
	n := len(slots)
	if n == 0 || s == "" || len(s) > 65535 {
		return 0
	}
	h := labHash(s)
	mask := uint32(n - 1)
	i := h & mask
	for {
		sl := slots[i]
		if sl.n == 0 {
			return 0
		}
		if sl.hash == h && int(sl.n) == len(s) &&
			string(domLabBytes[sl.off:sl.off+uint32(sl.n)]) == s {
			return sl.code
		}
		i = (i + 1) & mask
	}
}

func domTag(d string) int {
	ensureDom()
	d = CleanLowerDomain(d)
	if d == "" {
		return tagNone
	}
	state := int(domRoot)
	best := tagNone
	end := len(d)
	for end > 0 {
		start := end
		for start > 0 && d[start-1] != '.' {
			start--
		}
		code := labLookup(d[start:end])
		if code == 0 {
			break
		}
		next := domChild(state, code)
		if next == 0 {
			break
		}
		state = next
		tg := byte(domInfo[state] & 0xf)
		suf := int(tg & 3)
		if suf == tagForeign {
			return tagForeign
		}
		if suf == tagCN {
			best = tagCN
		}
		if start == 0 {
			ex := int((tg >> 2) & 3)
			if ex == tagForeign {
				return tagForeign
			}
			if ex == tagCN {
				best = tagCN
			}
			break
		}
		end = start - 1
	}
	return best
}

func domChild(s int, code uint32) int {
	f := int(domInfo[s] >> 4)
	if f == 0 {
		return 0
	}
	b := int(domBase[s])
	lo := b + 1
	hi := lo + f
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		c := domLab[m]
		if c < code {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if lo < b+1+f && domLab[lo] == code {
		return lo
	}
	return 0
}
