package main

import (
	"net/netip"
	"os"
	"regexp"
	"testing"

	"arc/core/internal/router"
	"arc/core/internal/store"
	"arc/core/internal/store/storetest"
)

func TestKernelIntegrity(t *testing.T) {
	storetest.Require(t)
	if router.MatchIP(netip.MustParseAddr("192.168.1.1")) != router.ActionLAN {
		t.Fatal("LAN 识别异常")
	}
	if router.MatchIP(netip.MustParseAddr("::ffff:192.168.1.1")) != router.ActionLAN {
		t.Fatal("IPv4-mapped LAN 识别异常")
	}
	if router.MatchIP(netip.MustParseAddr("142.250.72.196")) != router.ActionProxy || !router.IsGoogleIP(netip.MustParseAddr("142.250.72.196")) {
		t.Fatal("Google IP 表未优先于 CN 表")
	}
	if router.MatchDomain("dl.google.com") != router.ActionProxy || router.MatchDomain("www.google.com") != router.ActionProxy {
		t.Fatal("Google 域名未走代理")
	}
	if router.MatchDomain("v.qq.com") != router.ActionDirect || router.MatchDomain("www.baidu.com") != router.ActionDirect {
		t.Fatal("国内域名未直连")
	}
	if len(store.Get().Regions) != len(wantNodes) {
		t.Fatalf("地区数 %d, 期望 %d", len(store.Get().Regions), len(wantNodes))
	}
	// Counts are pinned for the synthetic fixture only; a real table
	// (ARC_NODES) is checked by the private tests.
	synthetic := os.Getenv("ARC_NODES") == ""
	nameRe := regexp.MustCompile(`^\p{Han}+ \d+$`)
	for i, a := range store.Get().Regions {
		seen := map[string]bool{}
		for _, n := range a.Nodes {
			if seen[n.Name] || !nameRe.MatchString(n.Name) {
				t.Fatalf("节点名未清洗或重复: %s (region %s)", n.Name, a.Name)
			}
			seen[n.Name] = true
		}
		if synthetic && len(a.Nodes) != wantNodes[a.Name] {
			t.Fatalf("%s 节点数 %d, 期望 %d", a.Name, len(a.Nodes), wantNodes[a.Name])
		}
		t.Logf("地区 [%d] %-8s 清洗完成 -> 共 %d 个精选节点", i, a.Name, len(a.Nodes))
	}
}
