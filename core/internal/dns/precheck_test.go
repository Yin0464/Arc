package dns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"arc/core/internal/dnswire"
	"arc/core/internal/router"
)

// precheckStub answers remote (pre-check) queries with remoteIP and domestic
// ones with domesticIP, counting each side.
func precheckStub(t *testing.T, remoteIP, domesticIP netip.Addr, remoteErr error) (remote, domestic *atomic.Int32) {
	t.Helper()
	remote, domestic = new(atomic.Int32), new(atomic.Int32)
	withUpstream(t, func(ctx context.Context, q []byte, isRemote bool) ([]byte, error) {
		_, qt, qEnd, _ := dnswire.Question(q)
		ip := domesticIP
		if isRemote {
			remote.Add(1)
			if remoteErr != nil {
				return nil, remoteErr
			}
			ip = remoteIP
		} else {
			domestic.Add(1)
		}
		if qt != dnswire.TypeA {
			return dnswire.Answer(q, qEnd, 0, 0, 0, nil), nil
		}
		return dnswire.Answer(q, qEnd, 0, qt, 60, ip.AsSlice()), nil
	})
	t.Cleanup(router.ClearLearned)
	router.ClearLearned()
	return remote, domestic
}

// An unknown name whose pre-check answer is in the CN table goes direct: the
// client gets the domestic DoH answer and the verdict is learned.
func TestPrecheckCNAnswerGoesDirect(t *testing.T) {
	const name = "precheck-cn.test"
	if router.MatchDomain(name) != router.ActionUnknown {
		t.Skip("test name matched a rule")
	}
	real := netip.MustParseAddr("180.101.49.44")
	remote, domestic := precheckStub(t, netip.MustParseAddr("114.114.114.114"), real, nil)
	resp := Answer(context.Background(), dnswire.Query(name, dnswire.TypeA))
	if ip, _ := dnswire.FirstIP(resp); ip != real {
		t.Fatalf("got %v, want domestic answer", ip)
	}
	if remote.Load() == 0 || domestic.Load() != 1 {
		t.Fatalf("remote=%d domestic=%d", remote.Load(), domestic.Load())
	}
	if router.MatchDomain(name) != router.ActionDirect {
		t.Fatal("direct verdict not learned")
	}
	n := remote.Load()
	Answer(context.Background(), dnswire.Query(name, dnswire.TypeAAAA))
	if remote.Load() != n {
		t.Fatal("learned name pre-checked again")
	}
}

// A non-CN pre-check answer keeps the name on the node: FakeIP, no domestic
// lookup.
func TestPrecheckForeignAnswerStaysProxied(t *testing.T) {
	const name = "precheck-foreign.test"
	remote, domestic := precheckStub(t, netip.MustParseAddr("203.0.113.9"), netip.Addr{}, nil)
	if !isFake(t, Answer(context.Background(), dnswire.Query(name, dnswire.TypeA))) {
		t.Fatal("not fake-ip")
	}
	if remote.Load() == 0 || domestic.Load() != 0 {
		t.Fatalf("remote=%d domestic=%d", remote.Load(), domestic.Load())
	}
	if router.MatchDomain(name) != router.ActionProxy {
		t.Fatal("proxy verdict not learned")
	}
}

// A failed pre-check falls back to FakeIP and is not learned, so the next
// query checks again.
func TestPrecheckFailureFakeIPNotLearned(t *testing.T) {
	const name = "precheck-fail.test"
	remote, domestic := precheckStub(t, netip.Addr{}, netip.Addr{}, context.DeadlineExceeded)
	if !isFake(t, Answer(context.Background(), dnswire.Query(name, dnswire.TypeA))) {
		t.Fatal("not fake-ip")
	}
	if domestic.Load() != 0 || router.MatchDomain(name) != router.ActionUnknown {
		t.Fatal("failed pre-check learned or went domestic")
	}
	n := remote.Load()
	Answer(context.Background(), dnswire.Query(name, dnswire.TypeA))
	if remote.Load() == n {
		t.Fatal("failure was cached")
	}
}

// A cache flush while the pre-check is in flight answers SERVFAIL rather than
// a verdict from the old network.
func TestPrecheckInflightClearServfail(t *testing.T) {
	const name = "precheck-inflight.test"
	var once sync.Once
	var entered atomic.Int32
	release := make(chan struct{})
	withUpstream(t, func(ctx context.Context, q []byte, isRemote bool) ([]byte, error) {
		if entered.Add(1) == 2 {
			once.Do(func() { close(release) })
		}
		time.Sleep(30 * time.Millisecond)
		_, qt, qEnd, _ := dnswire.Question(q)
		return dnswire.Answer(q, qEnd, 0, qt, 60, nil), nil
	})
	t.Cleanup(router.ClearLearned)
	go func() { <-release; ClearCache() }()
	resp := Answer(context.Background(), dnswire.Query(name, dnswire.TypeA))
	if dnswire.Rcode(resp) != 2 {
		t.Fatalf("rcode %d, want SERVFAIL", dnswire.Rcode(resp))
	}
}

// Foreign rule hits never reach any resolver.
func TestForeignRuleNoPrecheck(t *testing.T) {
	remote, domestic := precheckStub(t, netip.MustParseAddr("114.114.114.114"), netip.Addr{}, nil)
	for _, qt := range []uint16{dnswire.TypeA, dnswire.TypeAAAA, 65} {
		Answer(context.Background(), dnswire.Query("www.google.com", qt))
	}
	if remote.Load()+domestic.Load() != 0 {
		t.Fatal("foreign rule name went upstream")
	}
}

func TestCNDomainDoHDownServfail(t *testing.T) {
	stubUpstream(t, netip.Addr{}, true)
	resp := Answer(context.Background(), dnswire.Query("www.qq.com", dnswire.TypeA))
	if dnswire.Rcode(resp) != 2 {
		t.Fatalf("want SERVFAIL, got rcode %d", dnswire.Rcode(resp))
	}
}
