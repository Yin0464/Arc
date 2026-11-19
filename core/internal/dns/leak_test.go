package dns

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"arc/core/internal/dnswire"
	"arc/core/internal/router"
)

type upCall struct {
	name   string
	remote bool
}

func stubUpstream(t *testing.T, ip netip.Addr, fail bool) *[]upCall {
	t.Helper()
	var mu sync.Mutex
	calls := &[]upCall{}
	old := upstream.Load()
	f := dohFunc(func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		name, qtype, qEnd, _ := dnswire.Question(q)
		mu.Lock()
		*calls = append(*calls, upCall{name, remote})
		mu.Unlock()
		if fail {
			return nil, errors.New("down")
		}
		if qtype != dnswire.TypeA {
			return dnswire.Answer(q, qEnd, 0, 0, 0, nil), nil
		}
		b := ip.As4()
		return dnswire.Answer(q, qEnd, 0, dnswire.TypeA, 60, b[:]), nil
	})
	upstream.Store(&dohBox{f})
	t.Cleanup(func() { upstream.Store(old); ClearCache(); router.ClearLearned() })
	ClearCache()
	router.ClearLearned()
	return calls
}

func isFake(t *testing.T, resp []byte) bool {
	t.Helper()
	ip, err := dnswire.FirstIP(resp)
	if err != nil {
		t.Fatalf("no answer: %x", resp)
	}
	_, ok := GlobalFakeIP.Lookup(ip)
	return ok
}

func TestUnknownNameClassifiedRemotely(t *testing.T) {
	const name = "leak-probe-foreign.test"
	if router.MatchDomain(name) != router.ActionUnknown {
		t.Skip("test name matched a rule")
	}
	calls := stubUpstream(t, netip.MustParseAddr("203.0.113.9"), false)
	if router.MatchIP(netip.MustParseAddr("203.0.113.9")) == router.ActionDirect {
		t.Skip("documentation IP routed direct")
	}
	resp := Answer(context.Background(), dnswire.Query(name, dnswire.TypeA))
	if !isFake(t, resp) {
		t.Fatalf("not fake-ip: %x", resp)
	}
	for _, c := range *calls {
		if !c.remote {
			t.Fatalf("domestic resolver saw %q", c.name)
		}
	}
	if len(*calls) != 2 {
		t.Fatalf("calls %v", *calls)
	}

	n := len(*calls)
	Answer(context.Background(), dnswire.Query(name, dnswire.TypeAAAA))
	if len(*calls) != n {
		t.Fatalf("AAAA went upstream: %v", *calls)
	}
}

func TestUnknownNameProxyDownFailsClosed(t *testing.T) {
	const name = "leak-probe-down.test"
	calls := stubUpstream(t, netip.Addr{}, true)
	resp := Answer(context.Background(), dnswire.Query(name, dnswire.TypeA))
	if !isFake(t, resp) {
		t.Fatalf("not fake-ip: %x", resp)
	}
	for _, c := range *calls {
		if !c.remote {
			t.Fatalf("domestic resolver used: %v", *calls)
		}
	}
}

func TestProxyRuleNameNoUpstream(t *testing.T) {
	const name = "leak-probe-proxy.test"
	calls := stubUpstream(t, netip.MustParseAddr("203.0.113.9"), false)
	router.LearnDomain(name, router.ActionProxy)
	for _, qt := range []uint16{dnswire.TypeA, dnswire.TypeAAAA, 65, 16} {
		Answer(context.Background(), dnswire.Query(name, qt))
	}
	if len(*calls) != 0 {
		t.Fatalf("upstream used: %v", *calls)
	}
}

func TestDirectNameDomesticOnly(t *testing.T) {
	const name = "leak-probe-direct.test"
	calls := stubUpstream(t, netip.MustParseAddr("203.0.113.9"), false)
	router.LearnDomain(name, router.ActionDirect)
	resp := Answer(context.Background(), dnswire.Query(name, dnswire.TypeA))
	if isFake(t, resp) {
		t.Fatal("direct name got fake-ip")
	}
	if len(*calls) != 1 || (*calls)[0].remote {
		t.Fatalf("calls %v", *calls)
	}
}

func TestCNDomainDirectNoRemote(t *testing.T) {
	calls := stubUpstream(t, netip.MustParseAddr("203.0.113.9"), false)
	for _, n := range []string{"m.baidu.com", "www.qq.com", "img.alicdn.com"} {
		if router.MatchDomain(n) != router.ActionDirect {
			t.Fatalf("%s not direct", n)
		}
		resp := Answer(context.Background(), dnswire.Query(n, dnswire.TypeA))
		if isFake(t, resp) {
			t.Fatalf("%s got fake-ip", n)
		}
	}
	for _, c := range *calls {
		if c.remote {
			t.Fatalf("remote lookup for CN name: %v", *calls)
		}
	}
	if router.MatchDomain("baidu.com.evil.example") != router.ActionUnknown {
		t.Fatal("suffix match too loose")
	}
}

func TestGoogleBeforeCN(t *testing.T) {
	stubUpstream(t, netip.MustParseAddr("180.163.150.34"), false)
	for _, d := range []string{"dl.google.com", "redirector.gvt1.com", "googleapis.cn", "google.cn"} {
		if router.MatchDomain(d) != router.ActionProxy {
			t.Fatalf("%s must be proxied", d)
		}
	}
	if router.MatchDomain("baidu.cn") != router.ActionDirect {
		t.Fatal("baidu.cn must be direct")
	}
	if !isFake(t, Answer(context.Background(), dnswire.Query("dl.google.com", dnswire.TypeA))) {
		t.Fatal("dl.google.com went direct")
	}
	g := netip.MustParseAddr("142.250.72.196")
	if router.MatchIP(g) != router.ActionProxy {
		t.Fatal("Google IP not proxied")
	}
	router.NoteDirectIP(g, time.Minute)
	if router.IsDirectIP(g) {
		t.Fatal("Google IP noted direct")
	}
}

func TestCNIPv6AnswerDirect(t *testing.T) {
	if router.MatchIP(netip.MustParseAddr("240e:e9:6002::1")) != router.ActionDirect {
		t.Fatal("CN IPv6 not direct")
	}
}
