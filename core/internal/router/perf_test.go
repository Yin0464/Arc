package router

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestCNData(t *testing.T) {
	for _, c := range []struct {
		ip   string
		want Action
	}{
		{"114.114.114.114", ActionDirect}, {"223.5.5.5", ActionDirect}, {"180.101.49.44", ActionDirect},
		{"8.8.8.8", ActionProxy}, {"1.1.1.1", ActionProxy},
		{"203.208.40.66", ActionDirect}, {"142.250.72.196", ActionProxy},
		{"10.1.2.3", ActionLAN}, {"fd00::1", ActionLAN},
		{"240e:e9:6002::1", ActionDirect}, {"2408:8000::1", ActionDirect},
		{"2001:4860:4860::8888", ActionProxy}, {"2401:3800::1", ActionDirect},
	} {
		if got := MatchIP(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("%s: %v want %v", c.ip, got, c.want)
		}
	}
	for d, want := range map[string]bool{
		"baidu.com": true, "m.baidu.com": true, "WWW.QQ.COM.": true, "img.alicdn.com": true, "bdstatic.com": true,
		"google.com": false, "dl.google.com": false, "gstatic.com": false, "redirector.gvt1.com": false,
		"baidu.com.evil.example": false, "com": false, "": false, "example.org": false,
	} {
		if got := isCNDomain(d); got != want {
			t.Errorf("isCNDomain(%q)=%v", d, got)
		}
	}
}

var sink bool

func BenchmarkCN(b *testing.B) {
	ips := []uint32{0x08080808, 0x7272_7272, 0xb4653_12c, 0xcbd02801, 0x01000100, 0xdf050505}
	b.Run("ipv4", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			sink = ipTag4(ips[i%len(ips)]) == tagCN
		}
	})
	v6 := []uint64{0x240e00e960020000, 0x2001486048600000, 0x2408800000000000, 0x2a00145000000000}
	b.Run("ipv6", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			sink = ipTag6(v6[i%len(v6)]) == tagCN
		}
	})
	doms := []string{"m.baidu.com", "www.google.com", "img.alicdn.com", "a.b.c.d.example.org", "github.com", "api.weibo.cn"}
	b.Run("domain", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			sink = isCNDomain(doms[i%len(doms)])
		}
	})
	_ = fmt.Sprint
}

func BenchmarkMatch(b *testing.B) {
	v4 := []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("114.114.114.114"), netip.MustParseAddr("180.101.49.44"), netip.MustParseAddr("142.250.72.196"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("223.5.5.5")}
	v6 := []netip.Addr{netip.MustParseAddr("240e:e9:6002::1"), netip.MustParseAddr("2001:4860:4860::8888"), netip.MustParseAddr("2408:8000::1"), netip.MustParseAddr("2a00:1450::1")}
	doms := []string{"m.baidu.com", "www.google.com", "img.alicdn.com", "a.b.c.d.example.org", "github.com", "api.weibo.cn", "dl.google.com", "googleapis.cn"}
	b.Run("ipv4", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			sink = MatchIP(v4[i%len(v4)]) == ActionDirect
		}
	})
	b.Run("ipv6", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			sink = MatchIP(v6[i%len(v6)]) == ActionDirect
		}
	})
	b.Run("domain", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			sink = MatchDomain(doms[i%len(doms)]) == ActionDirect
		}
	})
}
