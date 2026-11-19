package dns

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"arc/core/internal/dnswire"
	"arc/core/internal/router"
)

func TestCarrierDomainsDirect(t *testing.T) {
	for _, d := range []string{"txwk.10010.com", "m.client.10010.com", "u.10010.cn", "wo.cn", "chinaunicom.cn", "chinaunicom.com", "186.cn", "10086.cn", "189.cn", "10000.com", "ctyun.cn", "17wo.cn"} {
		if !router.IsCarrierDomain(d) || router.MatchDomain(d) != router.ActionDirect || !router.IsCNDomain(d) {
			t.Fatalf("%s not carrier/direct", d)
		}
		if _, fake := TryFastFakeIP(dnswire.Query(d, dnswire.TypeA)); fake {
			t.Fatalf("%s got fake IP", d)
		}
	}
	for _, d := range []string{"x10010.com", "google.com", "10010.com.evil.io"} {
		if router.IsCarrierDomain(d) {
			t.Fatalf("%s wrongly carrier", d)
		}
	}
}

func TestSystemDNSAndV6Policy(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	var mu sync.Mutex
	var seen []string
	go func() {
		b := make([]byte, 1500)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			d, qt, qe, _ := dnswire.Question(b[:n])
			mu.Lock()
			seen = append(seen, d)
			mu.Unlock()
			ip := netip.MustParseAddr("10.0.0.172")
			if qt == dnswire.TypeA {
				pc.WriteTo(dnswire.Answer(b[:n], qe, 0, qt, 60, ip.AsSlice()), a)
			}
		}
	}()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	f := dohFunc(func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		_, qt, qe, _ := dnswire.Question(q)
		if qt == dnswire.TypeAAAA {
			return dnswire.Answer(q, qe, 0, qt, 60, netip.MustParseAddr("2408:8000::1").AsSlice()), nil
		}
		return dnswire.Answer(q, qe, 0, qt, 60, netip.MustParseAddr("1.2.4.8").AsSlice()), nil
	})
	old := upstream.Swap(&dohBox{f})
	defer upstream.Store(old)
	ClearCache()
	defer SetUnderlying("", -1)

	SetUnderlying("", 1)
	list := []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), uint16(port))}
	sysDNS.Store(&list)
	ctx := context.Background()
	r := Answer(ctx, dnswire.Query("m.client.10010.com", dnswire.TypeA))
	if ip, _ := dnswire.FirstIP(r); ip.String() != "10.0.0.172" {
		t.Fatalf("carrier A via system DNS: got %v", ip)
	}
	r = Answer(ctx, dnswire.Query("www.baidu.com", dnswire.TypeA))
	if ip, _ := dnswire.FirstIP(r); ip.String() != "1.2.4.8" {
		t.Fatalf("baidu via DoH: got %v", ip)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, d := range seen {
		if !router.IsCarrierDomain(d) {
			t.Fatalf("non-carrier %s leaked to system DNS", d)
		}
	}
	if r = Answer(ctx, dnswire.Query("www.baidu.com", dnswire.TypeAAAA)); dnswire.AnswerCount(r) == 0 {
		t.Fatal("v6 network should get AAAA")
	}
	ClearCache()
	SetUnderlying("", 0)
	if r = Answer(ctx, dnswire.Query("www.baidu.com", dnswire.TypeAAAA)); dnswire.AnswerCount(r) != 0 || dnswire.Rcode(r) != 0 {
		t.Fatal("v4-only network: want empty NOERROR AAAA")
	}

	if _, ok := TryFastFakeIP(dnswire.Query("www.google.com", dnswire.TypeAAAA)); !ok {
		t.Fatal("google AAAA should stay fake")
	}

	SetUnderlying("", -1)
	list2 := []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.3"), 9)}
	sysDNS.Store(&list2)
	r = Answer(ctx, dnswire.Query("u.10010.cn", dnswire.TypeA))
	if ip, _ := dnswire.FirstIP(r); ip.String() != "1.2.4.8" {
		t.Fatalf("fallback: got %v", ip)
	}
}

func TestSystemDNSIgnoresFastServfail(t *testing.T) {
	serve := func(rcode byte, delay time.Duration, ip netip.Addr) *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			buf := make([]byte, 1500)
			for {
				n, addr, err := c.ReadFromUDP(buf)
				if err != nil {
					return
				}
				q := append([]byte(nil), buf[:n]...)
				if delay > 0 {
					time.Sleep(delay)
				}
				_, _, qe, ok := dnswire.Question(q)
				if !ok {
					continue
				}
				var resp []byte
				if rcode != 0 {
					resp = dnswire.Answer(q, qe, rcode, dnswire.TypeA, 0, nil)
				} else {
					resp = dnswire.Answer(q, qe, 0, dnswire.TypeA, 60, ip.AsSlice())
				}
				_, _ = c.WriteToUDP(resp, addr)
			}
		}()
		return c
	}
	bad := serve(2, 0, netip.Addr{})
	t.Cleanup(func() { bad.Close() })
	good := serve(0, 40*time.Millisecond, netip.MustParseAddr("9.9.9.9"))
	t.Cleanup(func() { good.Close() })
	list := []netip.AddrPort{
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(bad.LocalAddr().(*net.UDPAddr).Port)),
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(good.LocalAddr().(*net.UDPAddr).Port)),
	}
	prev := sysDNS.Load()
	sysDNS.Store(&list)
	t.Cleanup(func() { sysDNS.Store(prev) })
	resp, ok := SystemDNSQuery(context.Background(), dnswire.Query("slow-good.example", dnswire.TypeA))
	if !ok {
		t.Fatal("fast SERVFAIL hid the usable answer")
	}
	if ip, _ := dnswire.FirstIP(resp); ip.String() != "9.9.9.9" {
		t.Fatalf("got %v rcode %d", ip, dnswire.Rcode(resp))
	}
}

func TestV6NameFullEvictsOne(t *testing.T) {
	v6mu.Lock()
	prev := v6names
	v6names = make(map[netip.Addr]string, 4096)
	for i := 0; i < 4096; i++ {
		v6names[netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})] = "old.example"
	}
	v6mu.Unlock()
	t.Cleanup(func() {
		v6mu.Lock()
		v6names = prev
		v6mu.Unlock()
	})
	ip := netip.MustParseAddr("203.0.113.8")
	noteV6Name(ip, "new.example")
	if NameForV6(ip) != "new.example" {
		t.Fatal("new name missing")
	}
	v6mu.Lock()
	n := len(v6names)
	v6mu.Unlock()
	if n != 4096 {
		t.Fatalf("len=%d want 4096", n)
	}
	noteV6Name(ip, "newer.example")
	if NameForV6(ip) != "newer.example" {
		t.Fatal("refresh lost the name")
	}
	v6mu.Lock()
	n = len(v6names)
	v6mu.Unlock()
	if n != 4096 {
		t.Fatalf("refresh len=%d", n)
	}
}
