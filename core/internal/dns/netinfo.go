package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"arc/core/internal/dnswire"
	"arc/core/internal/protect"
)

var (
	sysDNS atomic.Pointer[[]netip.AddrPort]

	v6State atomic.Int32
)

func dnsListChanged(prev *[]netip.AddrPort, next []netip.AddrPort) bool {
	if prev == nil {
		return len(next) != 0
	}
	if len(*prev) != len(next) {
		return true
	}
	for i := range next {
		if (*prev)[i] != next[i] {
			return true
		}
	}
	return false
}

func SetUnderlying(servers string, v6 int) {
	var list []netip.AddrPort
	for _, s := range strings.Split(servers, ",") {
		s = strings.TrimSpace(s)
		if i := strings.IndexByte(s, '%'); i >= 0 {
			s = s[:i]
		}
		if a, err := netip.ParseAddr(s); err == nil && !a.IsUnspecified() && !a.IsLoopback() {
			list = append(list, netip.AddrPortFrom(a.Unmap(), 53))
		}
		if len(list) == 4 {
			break
		}
	}
	changed := dnsListChanged(sysDNS.Load(), list)
	if len(list) == 0 {
		sysDNS.Store(nil)
	} else {
		sysDNS.Store(&list)
	}
	if changed {
		ClearCache()
	}
	switch {
	case v6 > 0:
		v6State.Store(1)
	case v6 == 0:
		v6State.Store(2)
	default:
		v6State.Store(0)
	}
}

func noDirectV6() bool { return v6State.Load() == 2 }

func SystemDNSQuery(ctx context.Context, q []byte) ([]byte, bool) {
	p := sysDNS.Load()
	if p == nil {
		return nil, false
	}
	servers := *p
	resp, err := dnswire.Race(ctx, 2500*time.Millisecond, len(servers), func(ctx context.Context, i int) ([]byte, error) {
		resp, err := dnswire.Exchange(ctx, &sysDialer, servers[i], q)
		if err != nil {
			return nil, err
		}
		switch dnswire.Rcode(resp) {
		case 1, 2, 5: // FORMERR, SERVFAIL, REFUSED — let another server win
			return nil, errDNSRcode
		default:
			return resp, nil
		}
	})
	if err != nil || dnswire.Rcode(resp) == 2 {
		return nil, false
	}
	return resp, true
}

var (
	errDNSRcode = errors.New("dns rcode")
	sysDialer   = net.Dialer{Control: protect.Control}
)

func LookupDirect(ctx context.Context, domain string, qtype uint16) []netip.Addr {
	q := dnswire.Query(domain, qtype)
	resp, err := directAnswer(ctx, domain, qtype, q)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	dnswire.EachIP(resp, func(ip netip.Addr) bool { out = append(out, ip); return false })
	return out
}

var (
	v6mu    sync.Mutex
	v6names = make(map[netip.Addr]string, 64)
)

func noteV6Name(ip netip.Addr, domain string) {
	v6mu.Lock()
	if _, ok := v6names[ip]; !ok && len(v6names) >= 4096 {
		for k := range v6names {
			delete(v6names, k)
			break
		}
	}
	v6names[ip] = domain
	v6mu.Unlock()
}

func NameForV6(ip netip.Addr) string {
	v6mu.Lock()
	defer v6mu.Unlock()
	return v6names[ip]
}
