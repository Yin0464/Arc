package router

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func loadCNList(tb testing.TB) []string {
	// ARC_RULES: the rule-library dir the embedded tables came from (build.sh).
	dir := os.Getenv("ARC_RULES")
	if dir == "" {
		tb.Skip("ARC_RULES not set")
	}
	b, err := os.ReadFile(filepath.Join(dir, "accelerated-domains.china.conf"))
	if err != nil {
		tb.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if p := strings.Split(l, "/"); len(p) >= 3 {
			out = append(out, strings.ToLower(p[1]))
		}
	}
	return out
}

func revLabels(d string) string {
	ls := strings.Split(d, ".")
	var sb strings.Builder
	for i := len(ls) - 1; i >= 0; i-- {
		sb.WriteString(ls[i])
		sb.WriteByte('.')
	}
	return sb.String()
}

type frontCoded struct {
	data  []byte
	heads []uint32
	first []string
}

func buildFC(doms []string) *frontCoded {
	keys := make([]string, len(doms))
	for i, d := range doms {
		keys[i] = revLabels(d)
	}
	sort.Strings(keys)
	f := &frontCoded{}
	var prev string
	for i, k := range keys {
		if i%16 == 0 {
			f.heads = append(f.heads, uint32(len(f.data)))
			f.data = append(append(f.data, byte(len(k))), k...)
			f.first = append(f.first, string(f.data[len(f.data)-len(k):]))
		} else {
			c := 0
			for c < len(prev) && c < len(k) && prev[c] == k[c] && c < 255 {
				c++
			}
			f.data = append(append(f.data, byte(c), byte(len(k)-c)), k[c:]...)
		}
		prev = k
	}
	return f
}

func (f *frontCoded) has(key []byte) bool {
	i := sort.Search(len(f.first), func(i int) bool { return f.first[i] > string(key) }) - 1
	if i < 0 {
		return false
	}
	off, end := int(f.heads[i]), len(f.data)
	if i+1 < len(f.heads) {
		end = int(f.heads[i+1])
	}
	var cur [256]byte
	n := int(f.data[off])
	copy(cur[:], f.data[off+1:off+1+n])
	off += 1 + n
	for {
		if c := bytes.Compare(cur[:n], key); c == 0 {
			return true
		} else if c > 0 || off >= end {
			return false
		}
		c, l := int(f.data[off]), int(f.data[off+1])
		copy(cur[c:], f.data[off+2:off+2+l])
		n = c + l
		off += 2 + l
	}
}

func (f *frontCoded) match(d string) bool {
	var buf [256]byte
	n := 0
	end := len(d)
	for i := len(d) - 1; i >= -1; i-- {
		if i == -1 || d[i] == '.' {
			n += copy(buf[n:], d[i+1:end])
			buf[n] = '.'
			n++
			if f.has(buf[:n]) {
				return true
			}
			end = i
		}
	}
	return false
}

var benchDoms = []string{"m.baidu.com", "www.google.com", "img.alicdn.com", "a.b.c.d.example.org", "github.com", "api.weibo.cn"}

func BenchmarkDomAlt(b *testing.B) {
	doms := loadCNList(b)
	fc := buildFC(doms)
	b.Logf("frontcoded bytes=%d (+%d block index)", len(fc.data), len(fc.heads)*4+len(fc.heads)*16)
	b.Logf("dat blob   bytes=%d", len(domTab))
	set := make(map[string]struct{}, len(doms))
	for _, d := range doms {
		set[d] = struct{}{}
	}
	for _, d := range benchDoms {
		if fc.match(d) != isCNDomain(d) {
			b.Fatalf("mismatch %s", d)
		}
	}
	b.Run("frontcoded", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			sink = fc.match(benchDoms[i%len(benchDoms)])
		}
	})
	b.Run("gomap", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			d := benchDoms[i%len(benchDoms)]
			r := false
			for j := -1; j < len(d); j++ {
				if j == -1 || d[j] == '.' {
					if _, ok := set[d[j+1:]]; ok {
						r = true
						break
					}
				}
			}
			sink = r
		}
	})
	b.Run("dat", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			sink = isCNDomain(benchDoms[i%len(benchDoms)])
		}
	})
}
