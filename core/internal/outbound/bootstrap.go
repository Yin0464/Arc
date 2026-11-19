package outbound

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"arc/core/internal/dnswire"
	"arc/core/internal/protect"
)

// DNS runs in two tiers.
//
// Tier 1 (BootstrapDNS) is domestic plaintext DNS on port 53 (UDP, TCP when
// truncated). It only resolves the hostnames of tier-2 servers.
//
// Tier 2 is DoH: DomesticDoHUrls for domestic names, and the per-protocol
// private DoH (Catalog.Profile(proto).DoHUrls) for node endpoints. Both
// tier-2 hostnames are resolved by tier 1 directly; nothing falls back to
// system DNS.
var (
	BootstrapDNS = [2]netip.AddrPort{
		netip.MustParseAddrPort("223.5.5.5:53"),
		netip.MustParseAddrPort("119.29.29.29:53"),
	}
	DomesticDoHUrls = [2]string{
		"https://dns.alidns.com/dns-query",
		"https://doh.pub/dns-query",
	}
)

const (
	bootstrapTimeout        = 2500 * time.Millisecond
	bootstrapStale          = time.Hour
	bootstrapTTLMin  uint32 = 60
	bootstrapTTLMax  uint32 = 600
)

var errBootstrapRcode = errors.New("bootstrap dns: no usable answer")

type dohIP struct {
	gen     uint64
	ip      netip.Addr
	expires time.Time
}

var (
	dohIPCache sync.Map // host -> dohIP
	dohIPLocks sync.Map // host -> *sync.Mutex
)

func loadDoHIP(host string, gen uint64) (dohIP, bool) {
	v, ok := dohIPCache.Load(host)
	if !ok {
		return dohIP{}, false
	}
	e := v.(dohIP)
	return e, e.gen == gen
}

func storeDoHIP(host string, ip netip.Addr, ttl uint32, gen uint64) {
	if flowGen.Load() != gen {
		return
	}
	ttl = min(max(ttl, bootstrapTTLMin), bootstrapTTLMax)
	dohIPCache.Store(host, dohIP{gen, ip, time.Now().Add(time.Duration(ttl) * time.Second)})
}

// resolveBootstrapHost returns the address of a tier-2 DoH host via tier 1.
// A same-generation entry past its TTL is still served for up to an hour
// when tier 1 fails.
func resolveBootstrapHost(ctx context.Context, host string, gen uint64) (netip.Addr, error) {
	if e, ok := loadDoHIP(host, gen); ok && time.Now().Before(e.expires) {
		return e.ip, nil
	}
	mu, _ := dohIPLocks.LoadOrStore(host, new(sync.Mutex))
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()
	e, ok := loadDoHIP(host, gen)
	if ok && time.Now().Before(e.expires) {
		return e.ip, nil
	}
	ip, ttl, err := queryBootstrap(ctx, host)
	if err != nil {
		if ok && time.Now().Before(e.expires.Add(bootstrapStale)) {
			return e.ip, nil
		}
		return netip.Addr{}, err
	}
	storeDoHIP(host, ip, ttl, gen)
	return ip, nil
}

type bootstrapAnswer struct {
	ip  netip.Addr
	ttl uint32
}

func queryBootstrap(ctx context.Context, host string) (netip.Addr, uint32, error) {
	q := dnswire.Query(host, dnswire.TypeA)
	servers := BootstrapDNS
	a, err := dnswire.Race(ctx, bootstrapTimeout, len(servers), func(ctx context.Context, i int) (bootstrapAnswer, error) {
		resp, err := dnswire.Exchange(ctx, protect.Dialer(), servers[i], q)
		if err != nil {
			return bootstrapAnswer{}, err
		}
		if dnswire.Rcode(resp) != 0 {
			return bootstrapAnswer{}, errBootstrapRcode
		}
		ip, err := dnswire.FirstIP(resp)
		if err != nil {
			return bootstrapAnswer{}, errBootstrapRcode
		}
		return bootstrapAnswer{ip, dnswire.MinTTL(resp)}, nil
	})
	return a.ip, a.ttl, err
}

// DoHRacer implements dns.DoH: domestic names race DomesticDoHUrls direct;
// remote pre-check queries go through the active node.
type DoHRacer struct{}

func (DoHRacer) Race(ctx context.Context, q []byte, remote bool) ([]byte, error) {
	if remote {
		return RaceRemoteDoH(ctx, q)
	}
	return RaceDoHServers(ctx, DomesticDoHUrls[:], q)
}

func (DoHRacer) CloseRemote() { CloseRemoteDoH() }
