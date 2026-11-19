package router

import (
	"net/netip"
	"sync"
	"time"
)

const maxDirectIPs = 4096

var (
	dipMu sync.RWMutex
	dips  = make(map[netip.Addr]int64, 256)

	nowUnix = func() int64 { return time.Now().Unix() }
)

func NoteDirectIP(addr netip.Addr, ttl time.Duration) {
	addr = addr.Unmap()
	if IsGoogleIP(addr) {
		return
	}
	exp := nowUnix() + int64(ttl/time.Second)
	dipMu.Lock()
	if _, exists := dips[addr]; !exists && len(dips) >= maxDirectIPs {
		now := nowUnix()
		for a, e := range dips {
			if e <= now {
				delete(dips, a)
			}
		}
		if len(dips) >= maxDirectIPs {
			for a := range dips {
				delete(dips, a)
				break
			}
		}
	}
	if dips[addr] < exp {
		dips[addr] = exp
	}
	dipMu.Unlock()
}

func IsDirectIP(addr netip.Addr) bool {
	dipMu.RLock()
	e, ok := dips[addr.Unmap()]
	dipMu.RUnlock()
	return ok && e > nowUnix()
}

func ClearDirectIPs() {
	dipMu.Lock()
	clear(dips)
	dipMu.Unlock()
}
