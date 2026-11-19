package dns

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"arc/core/internal/dnswire"
	"arc/core/internal/router"
)

type FakeIPPool struct {
	mu          sync.RWMutex
	cursor      uint16
	idxToDomain [65536]string
	domainToIdx map[string]uint16
	gen         atomic.Uint64
}

var GlobalFakeIP = &FakeIPPool{
	cursor:      1,
	domainToIdx: make(map[string]uint16, 4096),
}

func (p *FakeIPPool) Allocate(domain string, isIPv6 bool) netip.Addr {
	p.mu.RLock()
	if idx, ok := p.domainToIdx[domain]; ok {
		p.mu.RUnlock()
		return slotToAddr(idx, isIPv6)
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	if idx, ok := p.domainToIdx[domain]; ok {
		return slotToAddr(idx, isIPv6)
	}

	// Slots fill in cursor order and are only freed all at once (Invalidate),
	// so the next slot is either free or holds the oldest mapping.
	const minSlot, maxSlot uint16 = 2, 65534
	if p.cursor++; p.cursor < minSlot || p.cursor > maxSlot {
		p.cursor = minSlot
	}
	idx := p.cursor
	delete(p.domainToIdx, p.idxToDomain[idx])
	p.idxToDomain[idx] = domain
	p.domainToIdx[domain] = idx
	return slotToAddr(idx, isIPv6)
}

var fakeV6Prefix = [14]byte{0xfd, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x00, 0xff}

const FakeTTL = 60

func fakeSlot(ip netip.Addr) (uint16, bool) {
	ip = ip.Unmap()
	if ip.Is4() {
		b := ip.As4()
		if b[0] != 198 || b[1] != 18 {
			return 0, false
		}
		return uint16(b[2])<<8 | uint16(b[3]), true
	}
	if ip.Is6() {
		b := ip.As16()
		if [14]byte(b[:14]) != fakeV6Prefix {
			return 0, false
		}
		return uint16(b[14])<<8 | uint16(b[15]), true
	}
	return 0, false
}

func InFakeRange(ip netip.Addr) bool { _, ok := fakeSlot(ip); return ok }

// LookupDest classifies ip against the FakeIP pool: mapped domain, or orphan
// (in range but unmapped). found and orphan are mutually exclusive.
func LookupDest(ip netip.Addr) (domain string, found, orphan bool) {
	if domain, found = GlobalFakeIP.Lookup(ip); found {
		return domain, true, false
	}
	if InFakeRange(ip) {
		return "", false, true
	}
	return "", false, false
}

func (p *FakeIPPool) Lookup(ip netip.Addr) (string, bool) {
	idx, ok := fakeSlot(ip)
	if !ok {
		return "", false
	}
	p.mu.RLock()
	domain := p.idxToDomain[idx]
	p.mu.RUnlock()
	return domain, domain != ""
}

func (p *FakeIPPool) Invalidate() {
	p.mu.Lock()
	clear(p.domainToIdx)
	for i := range p.idxToDomain {
		p.idxToDomain[i] = ""
	}
	p.cursor = 1
	p.gen.Add(1)
	p.mu.Unlock()
}

func slotToAddr(idx uint16, isIPv6 bool) netip.Addr {
	hi, lo := byte(idx>>8), byte(idx&0xFF)
	if isIPv6 {
		var b [16]byte
		copy(b[:], fakeV6Prefix[:])
		b[14], b[15] = hi, lo
		return netip.AddrFrom16(b)
	}
	return netip.AddrFrom4([4]byte{198, 18, hi, lo})
}

const slowDNSTimeout = 5 * time.Second

func Resolve(ctx context.Context, q []byte, reply func([]byte)) {
	if r, ok := TryFastFakeIP(q); ok {
		reply(r)
		return
	}
	q = append([]byte(nil), q...)
	go func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), slowDNSTimeout)
		defer cancel()
		if r := HandleSlowDNS(dctx, q); len(r) > 0 {
			reply(r)
		}
	}()
}

func Answer(ctx context.Context, q []byte) []byte {
	if r, ok := TryFastFakeIP(q); ok {
		return r
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, slowDNSTimeout)
		defer cancel()
	}
	return HandleSlowDNS(ctx, q)
}

func TryFastFakeIP(rawQuery []byte) ([]byte, bool) {
	domain, qtype, qEnd, ok := dnswire.Question(rawQuery)
	if !ok || (qtype != dnswire.TypeA && qtype != dnswire.TypeAAAA) || router.MatchDomain(domain) != router.ActionProxy {
		return nil, false
	}
	return fakeAnswer(rawQuery, qtype, qEnd, domain), true
}

func HandleSlowDNS(ctx context.Context, rawQuery []byte) []byte {
	domain, qtype, qEnd, ok := dnswire.Question(rawQuery)
	if !ok {
		return nil
	}
	if qtype != dnswire.TypeA && qtype != dnswire.TypeAAAA {
		return dnswire.Answer(rawQuery, qEnd, 0, 0, 0, nil)
	}

	act := router.MatchDomain(domain)
	if act == router.ActionUnknown {
		var err error
		if act, err = classify(ctx, domain); errors.Is(err, errCacheCleared) {
			return dnswire.Answer(rawQuery, qEnd, 2, 0, 0, nil)
		}
	}

	if router.IsDirectOrLAN(act) {
		if qtype == dnswire.TypeAAAA && noDirectV6() {
			return dnswire.Answer(rawQuery, qEnd, 0, 0, 0, nil)
		}
		if resp, err := directAnswer(ctx, domain, qtype, rawQuery); err == nil {
			if act == router.ActionDirect {
				ttl := time.Duration(max(dnswire.MinTTL(resp), 60)+600) * time.Second
				dnswire.EachIP(resp, func(ip netip.Addr) bool {
					if ip.Is6() && !ip.Is4In6() {
						noteV6Name(ip, domain)
					}
					if router.MatchIP(ip) == router.ActionProxy {
						router.NoteDirectIP(ip, ttl)
					}
					return false
				})
			}
			return resp
		}
		return dnswire.Answer(rawQuery, qEnd, 2, 0, 0, nil)
	}
	return fakeAnswer(rawQuery, qtype, qEnd, domain)
}

type cacheKey struct {
	domain string
	qtype  uint16
	remote bool
}

type cacheEntry struct {
	wire    []byte
	expires time.Time
	stale   time.Time
}

const (
	ttlFloor = 60
	ttlCap   = 600
	negMin   = 30
	negMax   = 300
	staleTTL = 10
	maxStale = time.Hour
)

func cacheTTL(resp []byte) uint32 {
	switch rc := dnswire.Rcode(resp); {
	case rc == 0 && dnswire.AnswerCount(resp) > 0:
		return min(max(dnswire.MinTTL(resp), ttlFloor), ttlCap)
	case rc == 0 || rc == 3:
		ttl, ok := dnswire.NegativeTTL(resp)
		if !ok {
			ttl = negMin
		}
		return min(max(ttl, negMin), negMax)
	}
	return 0
}

var (
	cacheMu  sync.Mutex
	cacheGen atomic.Uint64
	dnsCache = make(map[cacheKey]cacheEntry)
	flights  = map[cacheKey]*flight{}
)

type flight struct {
	done chan struct{}
	wire []byte
	err  error
}

const maxCache = 8192

// evictLocked runs when the cache is full: it drops every entry past its
// stale deadline and, if still full, the eighth closest to going stale, so a
// full cache costs one sort per maxCache/8 inserts instead of a scan each.
func evictLocked(now time.Time) {
	for k, e := range dnsCache {
		if !now.Before(e.stale) {
			delete(dnsCache, k)
		}
	}
	if len(dnsCache) < maxCache {
		return
	}
	keys := make([]cacheKey, 0, len(dnsCache))
	for k := range dnsCache {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b cacheKey) int { return dnsCache[a].stale.Compare(dnsCache[b].stale) })
	for _, k := range keys[:len(keys)/8] {
		delete(dnsCache, k)
	}
}

var errCacheCleared = errors.New("dns: cache cleared")

func ClearCache() {
	doh().CloseRemote()
	cacheMu.Lock()
	cacheGen.Add(1)
	clear(dnsCache)
	// Pre-clear flights still finish (with errCacheCleared) for their own
	// waiters; queries arriving from now on start a fresh lookup.
	clear(flights)
	cacheMu.Unlock()
}

func OnNetworkChanged() {
	ClearCache()
	GlobalFakeIP.Invalidate()
	router.ClearDirectIPs()
}

func withID(wire, q []byte) []byte {
	out := append([]byte(nil), wire...)
	if len(out) >= 2 && len(q) >= 2 {
		out[0], out[1] = q[0], q[1]
	}
	return out
}

var errNoLocalDNS = errors.New("dns: no underlying DNS for local name")

func directAnswer(ctx context.Context, domain string, qtype uint16, q []byte) ([]byte, error) {
	if router.IsLANDomain(domain) {
		if resp, ok := SystemDNSQuery(ctx, q); ok {
			return withID(resp, q), nil
		}
		return nil, errNoLocalDNS
	}
	if router.IsCarrierDomain(domain) {
		if resp, ok := SystemDNSQuery(ctx, q); ok {
			return withID(resp, q), nil
		}
	}
	return cachedDoH(ctx, domain, qtype, q)
}

func cachedDoH(ctx context.Context, domain string, qtype uint16, q []byte) ([]byte, error) {
	return cachedLookup(ctx, domain, qtype, q, false)
}

func remoteDoH(ctx context.Context, domain string, qtype uint16, q []byte) ([]byte, error) {
	return cachedLookup(ctx, domain, qtype, q, true)
}

// DoH races DNS-over-HTTPS upstreams for one wire query: remote (pre-check)
// queries leave through the active node, the rest go to the domestic
// encrypted servers direct. CloseRemote drops pooled remote connections after
// a cache flush.
type DoH interface {
	Race(ctx context.Context, q []byte, remote bool) ([]byte, error)
	CloseRemote()
}

type dohBox struct{ DoH }

var upstream atomic.Pointer[dohBox]

var errNoDoH = errors.New("dns: no DoH upstream")

type noDoH struct{}

func (noDoH) Race(context.Context, []byte, bool) ([]byte, error) { return nil, errNoDoH }
func (noDoH) CloseRemote()                                       {}

// SetDoH installs the DoH racer used for every upstream lookup.
func SetDoH(d DoH) { upstream.Store(&dohBox{d}) }

func doh() DoH {
	if b := upstream.Load(); b != nil {
		return b.DoH
	}
	return noDoH{}
}

func cachedLookup(ctx context.Context, domain string, qtype uint16, q []byte, remote bool) ([]byte, error) {
	k := cacheKey{domain, qtype, remote}
	now := time.Now()
	cacheMu.Lock()
	gen := cacheGen.Load()
	if e, ok := dnsCache[k]; ok {
		if now.Before(e.expires) {
			wire := e.wire
			cacheMu.Unlock()
			return withID(wire, q), nil
		}
		if now.Before(e.stale) {
			wire := e.wire
			if flights[k] == nil {
				f := &flight{done: make(chan struct{})}
				flights[k] = f
				go func() {
					rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_, _ = runFlight(rctx, k, f, q, gen)
				}()
			}
			cacheMu.Unlock()
			return dnswire.WithTTL(withID(wire, q), staleTTL), nil
		}
	}
	if f := flights[k]; f != nil {
		cacheMu.Unlock()
		select {
		case <-f.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if f.err != nil {
			return nil, f.err
		}
		return withID(f.wire, q), nil
	}
	f := &flight{done: make(chan struct{})}
	flights[k] = f
	cacheMu.Unlock()

	rctx, cancel := detachCancelKeepDeadline(ctx)
	defer cancel()
	return runFlight(rctx, k, f, q, gen)
}

func detachCancelKeepDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if dl, ok := ctx.Deadline(); ok {
		return context.WithDeadline(context.Background(), dl)
	}
	return context.WithCancel(context.Background())
}

func runFlight(ctx context.Context, k cacheKey, f *flight, q []byte, gen uint64) ([]byte, error) {
	resp, err := doh().Race(ctx, q, k.remote)
	if err == nil {
		if ttl := cacheTTL(resp); ttl > 0 {
			cacheMu.Lock()

			if cacheGen.Load() == gen {
				now := time.Now()
				if len(dnsCache) >= maxCache {
					evictLocked(now)
				}
				exp := now.Add(time.Duration(ttl) * time.Second)
				stale := exp
				if !k.remote && dnswire.AnswerCount(resp) > 0 && dnswire.Rcode(resp) == 0 {
					stale = exp.Add(maxStale)
				}
				dnsCache[k] = cacheEntry{append([]byte(nil), resp...), exp, stale}
			}
			cacheMu.Unlock()
		}
	}
	cacheMu.Lock()
	if err == nil && cacheGen.Load() != gen {
		err = errCacheCleared
		resp = nil
	}
	if err == nil {
		f.wire = append([]byte(nil), resp...)
	}
	f.err = err
	if flights[k] == f {
		delete(flights, k)
	}
	close(f.done)
	cacheMu.Unlock()
	return resp, err
}

func PrewarmDoH() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_, _ = cachedDoH(ctx, prewarmDirect, dnswire.TypeA, dnswire.Query(prewarmDirect, dnswire.TypeA))
	}()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_, _ = doh().Race(ctx, dnswire.Query(prewarmRemote, dnswire.TypeA), true)
	}()
}

const (
	prewarmDirect = "www.baidu.com"
	prewarmRemote = "www.google.com"
)

func fakeAnswer(req []byte, qtype uint16, qEnd int, domain string) []byte {
	ip := GlobalFakeIP.Allocate(domain, qtype == dnswire.TypeAAAA)
	return dnswire.Answer(req, qEnd, 0, qtype, FakeTTL, ip.AsSlice())
}

var aaaaGrace = 100 * time.Millisecond

// precheckTimeout is the overall deadline for one pre-check (A and AAAA
// together, including the AAAA grace). It equals the per-query DoH race
// timeout, so no answer that arrives in time is cut, and it leaves the rest of
// the 5s slow-DNS budget for the direct lookup that follows a direct verdict,
// whatever DoH racer is installed. It bounds latency only, not concurrency.
var precheckTimeout = 3 * time.Second

type probeResult struct {
	act router.Action
	err error
	isA bool
}

// classify is the pre-check for names no rule matches: it resolves A and AAAA
// through the node without connecting anywhere, then matches the answers
// against the IP table. Any CN address means direct; otherwise proxy. A
// verdict is learned; a failure is not, and the caller falls back to FakeIP.
func classify(ctx context.Context, domain string) (router.Action, error) {
	ctx, cancel := context.WithTimeout(ctx, precheckTimeout)
	defer cancel()
	ch := make(chan probeResult, 2)
	for _, qt := range [2]uint16{dnswire.TypeA, dnswire.TypeAAAA} {
		go func() {
			resp, err := remoteDoH(ctx, domain, qt, dnswire.Query(domain, qt))
			ch <- probeResult{verdict(resp, err), err, qt == dnswire.TypeA}
		}()
	}
	act, firstErr := router.ActionUnknown, error(nil)
	var grace <-chan time.Time
	for got := 0; got < 2; {
		select {
		case r := <-ch:
			got++
			switch {
			case r.act == router.ActionDirect:
				router.LearnDomain(domain, router.ActionDirect)
				return router.ActionDirect, nil
			case r.act == router.ActionProxy:
				act = router.ActionProxy
			case firstErr == nil:
				firstErr = r.err
			}
			if r.isA && got == 1 && act == router.ActionProxy {
				t := time.NewTimer(aaaaGrace)
				defer t.Stop()
				grace = t.C
			}
		case <-grace:
			got = 2
		case <-ctx.Done():
			if act == router.ActionProxy {
				router.LearnDomain(domain, act)
				return act, nil
			}
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			return router.ActionUnknown, firstErr
		}
	}
	if act == router.ActionProxy {
		router.LearnDomain(domain, act)
		return act, nil
	}
	return router.ActionUnknown, firstErr
}

func verdict(resp []byte, err error) router.Action {
	if err != nil || len(resp) < 4 {
		return router.ActionUnknown
	}
	switch resp[3] & 0x0F {
	case 0:
		if dnswire.AnswerCount(resp) == 0 {
			// NODATA says nothing about where the name lives.
			return router.ActionUnknown
		}
		act := router.ActionProxy
		dnswire.EachIP(resp, func(ip netip.Addr) bool {
			if router.MatchIP(ip) == router.ActionDirect {
				act = router.ActionDirect
				return true
			}
			return false
		})
		return act
	case 3:
		return router.ActionProxy
	}
	return router.ActionUnknown
}
