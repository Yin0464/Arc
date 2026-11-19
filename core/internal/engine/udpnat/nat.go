package udpnat

import (
	"arc/core/internal/dns"
	"arc/core/internal/outbound"
	"arc/core/internal/protect"
	"arc/core/internal/router"
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

func lanUnicast(a netip.Addr) bool {
	if a.IsMulticast() || a.IsUnspecified() || !a.IsValid() {
		return false
	}
	if a.Is4() {
		b := a.As4()
		return b[0] != 0 && b[3] != 255 && b[0] < 224
	}
	return true
}

type udpMsg struct {
	dst netip.AddrPort
	p   []byte
	box *[]byte
}

const udpPayCap = 2048

var udpPayPool = sync.Pool{New: func() any {
	b := make([]byte, udpPayCap)
	return &b
}}

func cloneUDP(p []byte) ([]byte, *[]byte) {
	if len(p) > udpPayCap {
		b := make([]byte, len(p))
		copy(b, p)
		return b, nil
	}
	box := udpPayPool.Get().(*[]byte)
	b := (*box)[:len(p)]
	copy(b, p)
	return b, box
}

func freeUDP(box *[]byte) {
	if box != nil {
		udpPayPool.Put(box)
	}
}

type udpSession struct {
	conn       net.PacketConn
	direct     bool
	fake       bool
	anchor     netip.AddrPort
	lastActive atomic.Int64
	idle       int64
	mu         sync.Mutex
	dead       bool
	out        chan udpMsg
}

// sessionQueue is the per-session upstream send queue (packets). It absorbs
// bursts while the upstream dial completes or the uplink is momentarily slow.
const sessionQueue = 512

func newUDPSession(pc net.PacketConn, direct, fake bool, anchor netip.AddrPort) *udpSession {
	s := &udpSession{conn: pc, direct: direct, fake: fake, anchor: anchor, idle: udpIdle(anchor.Port()), out: make(chan udpMsg, sessionQueue)}
	s.lastActive.Store(time.Now().Unix())
	return s
}

func (s *udpSession) enqueue(dst netip.AddrPort, p []byte) {
	b, box := cloneUDP(p)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead {
		freeUDP(box)
		return
	}
	select {
	case s.out <- udpMsg{dst, b, box}:
	default:
		freeUDP(box)
	}
}

func (s *udpSession) stop() {
	s.mu.Lock()
	if s.dead {
		s.mu.Unlock()
		return
	}
	s.dead = true
	close(s.out)
	c := s.conn
	s.mu.Unlock()
	if c != nil {

		_ = c.SetDeadline(time.Now())
		go c.Close()
	}
}

func (s *udpSession) releaseQueued() {
	for msg := range s.out {
		freeUDP(msg.box)
	}
}

func (s *udpSession) writeLoop() {
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	if c == nil {
		s.stop()
		s.releaseQueued()
		return
	}

	var refresh time.Time
	for msg := range s.out {
		if now := time.Now(); !now.Before(refresh) {
			_ = c.SetWriteDeadline(now.Add(30 * time.Second))
			refresh = now.Add(time.Second)
		}
		err := writeUDPMsg(c, msg)
		freeUDP(msg.box)
		if err != nil {
			s.stop()
			s.releaseQueued()
			return
		}
	}
}

func writeUDPMsg(c net.PacketConn, msg udpMsg) error {
	var addr net.Addr
	if domain, ok := dns.GlobalFakeIP.Lookup(msg.dst.Addr()); ok {
		addr = &outbound.PacketAddr{TargetAddr: outbound.TargetAddr{Domain: domain, Port: msg.dst.Port()}}
	} else {
		addr = net.UDPAddrFromAddrPort(msg.dst)
	}
	_, err := c.WriteTo(msg.p, addr)
	return err
}

func sessionReplyFrom(s *udpSession, addr net.Addr, src netip.AddrPort) netip.AddrPort {
	if s.fake || addr == nil {
		return s.anchor
	}
	var ip netip.Addr
	var port uint16
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a == nil || a.IP == nil {
			return s.anchor
		}
		ap := a.AddrPort()
		ip, port = ap.Addr().Unmap(), ap.Port()
	case *outbound.PacketAddr:
		if a == nil || a.Domain != "" || !a.IP.IsValid() {
			return s.anchor
		}
		ip, port = a.IP.Unmap(), a.Port
	default:
		return s.anchor
	}
	if !ip.IsValid() || ip.Is4() != src.Addr().Is4() {
		return s.anchor
	}
	return netip.AddrPortFrom(ip, port)
}

func (s *udpSession) readLoop(m *Manager, key natKey, writeBack func([]byte, netip.AddrPort)) {
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	if c == nil {
		m.retire(key, s)
		s.stop()
		return
	}
	buf := make([]byte, 65535)
	for {
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			break
		}
		s.lastActive.Store(time.Now().Unix())
		writeBack(buf[:n], sessionReplyFrom(s, addr, key.src))
	}
	m.retire(key, s)
	s.stop()
}

type natKey struct {
	src  netip.AddrPort
	kind uint8
}

const (
	natDirect uint8 = iota
	natProxy
	natFake
)

func natKind(direct, fake bool) uint8 {
	switch {
	case fake:
		return natFake
	case direct:
		return natDirect
	}
	return natProxy
}

// Manager is the UDP NAT table: one session per (source, route kind).
// FakeIP destinations carry their domain; real IPs route by the IP table.
type Manager struct {
	mu       sync.Mutex
	sessions map[natKey]*udpSession
	reaper   bool
	gen      uint64
}

// New returns an empty table.
func New() *Manager {
	return &Manager{sessions: make(map[natKey]*udpSession)}
}

func (m *Manager) ForwardPacket(src, dst netip.AddrPort, payload []byte, writeBack func([]byte, netip.AddrPort)) (refused bool) {
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	domain, fake, orphan := dns.LookupDest(dst.Addr())
	if fake {
		if router.IsDirectOrLAN(router.MatchDomain(domain)) {
			return true
		}
	} else if orphan {
		return true
	}
	direct := false
	if !fake {
		switch router.ResolveIPAction(dst.Addr()) {
		case router.ActionLAN:
			if !lanUnicast(dst.Addr()) {
				return false
			}
			direct = true
		case router.ActionDirect:
			direct = true
		}
	}
	if !direct && !outbound.ActiveSupportsUDP() {
		return true
	}
	now := time.Now().Unix()
	key := natKey{src, natKind(direct, fake)}
	m.mu.Lock()
	if sess := m.sessions[key]; sess != nil {
		sess.lastActive.Store(now)
		m.mu.Unlock()
		sess.enqueue(dst, payload)
		return false
	}
	victim, ok := m.admitOrEvictLocked()
	if !ok {
		m.mu.Unlock()
		return true
	}
	sess := newUDPSession(nil, direct, fake, dst)
	sess.lastActive.Store(now)
	sess.enqueue(dst, payload)
	m.sessions[key] = sess
	gen := m.gen
	startReaper := !m.reaper
	m.reaper = true
	m.mu.Unlock()
	if victim != nil {
		victim.stop()
	}
	if startReaper {
		go m.reaperLoop()
	}
	go sess.dial(m, gen, key, dst, writeBack, direct, fake, domain)
	return false
}

func (s *udpSession) dial(m *Manager, gen uint64, key natKey, dst netip.AddrPort, writeBack func([]byte, netip.AddrPort), direct, fake bool, domain string) {
	s.mu.Lock()
	dead := s.dead
	s.mu.Unlock()
	if dead {
		m.retire(key, s)
		s.releaseQueued()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var pc net.PacketConn
	var err error
	switch {
	case fake || domain != "":
		pc, err = outbound.DialUDP(ctx, outbound.TargetAddr{Domain: domain, Port: dst.Port()})
	case direct:
		pc, err = protect.ListenConfig().ListenPacket(ctx, "udp", "")
	default:
		pc, err = outbound.DialUDP(ctx, outbound.TargetAddr{IP: dst.Addr(), Port: dst.Port()})
	}
	if err != nil {
		m.abandon(key, s)
		s.releaseQueued()
		return
	}
	m.mu.Lock()
	stale := m.gen != gen || m.sessions[key] != s
	m.mu.Unlock()
	if stale {
		_ = pc.Close()
		s.stop()
		s.releaseQueued()
		return
	}
	s.mu.Lock()
	if s.dead {
		s.mu.Unlock()
		_ = pc.Close()
		s.releaseQueued()
		return
	}
	s.conn = pc
	s.mu.Unlock()
	go s.writeLoop()
	go s.readLoop(m, key, writeBack)
}

func (m *Manager) abandon(key natKey, s *udpSession) {
	m.retire(key, s)
	s.stop()
}

func (m *Manager) retire(key natKey, sess *udpSession) {
	m.mu.Lock()
	if m.sessions[key] == sess {
		delete(m.sessions, key)
	}
	m.mu.Unlock()
}

func (m *Manager) reaperLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()
		var dead []*udpSession
		m.mu.Lock()
		for src, sess := range m.sessions {
			if now-sess.lastActive.Load() > sess.idle {
				dead = append(dead, sess)
				delete(m.sessions, src)
			}
		}
		if len(m.sessions) == 0 {
			m.reaper = false
			m.mu.Unlock()
			for _, s := range dead {
				s.stop()
			}
			return
		}
		m.mu.Unlock()
		for _, s := range dead {
			s.stop()
		}
	}
}

func (m *Manager) ClearAll() {
	m.mu.Lock()
	m.gen++
	old := m.sessions
	m.sessions = make(map[natKey]*udpSession, len(old))
	m.mu.Unlock()
	for _, s := range old {
		s.stop()
	}
}

func udpIdle(port uint16) int64 {
	switch port {
	case 53, 123, 853, 5353:
		return 20
	case 443:
		return 300
	}
	return 60
}
