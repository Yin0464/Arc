package udpnat

import (
	"cmp"
	"slices"
	"time"
)

const (
	SessionLimit    = 256
	udpEvictMinIdle = int64(5)
)

func (m *Manager) admitOrEvictLocked() (victim *udpSession, ok bool) {
	if len(m.sessions) < SessionLimit {
		return nil, true
	}
	now := time.Now().Unix()
	var bestKey natKey
	var best *udpSession
	var bestIdle int64 = -1
	for k, s := range m.sessions {
		idle := now - s.lastActive.Load()
		if idle < udpEvictMinIdle {
			continue
		}
		if idle > bestIdle {
			bestIdle = idle
			bestKey = k
			best = s
		}
	}
	if best == nil {
		return nil, false
	}
	delete(m.sessions, bestKey)
	return best, true
}

func (m *Manager) EvictIdle(max int, minIdleSec int64) int {
	if max <= 0 {
		return 0
	}
	now := time.Now().Unix()
	type cand struct {
		k    natKey
		s    *udpSession
		idle int64
	}
	var list []cand
	m.mu.Lock()
	for k, s := range m.sessions {
		idle := now - s.lastActive.Load()
		if idle >= minIdleSec {
			list = append(list, cand{k, s, idle})
		}
	}
	slices.SortFunc(list, func(a, b cand) int { return cmp.Compare(b.idle, a.idle) })
	n := min(max, len(list))
	victims := make([]*udpSession, 0, n)
	for i := 0; i < n; i++ {
		delete(m.sessions, list[i].k)
		victims = append(victims, list[i].s)
	}
	m.mu.Unlock()
	for _, s := range victims {
		s.stop()
	}
	return len(victims)
}
