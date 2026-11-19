package engine

import (
	"arc/core/internal/dns"
	"arc/core/internal/engine/tun"
	"arc/core/internal/engine/udpnat"
	"arc/core/internal/engine/ustack"
	"arc/core/internal/protect"
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type CustomStack struct {
	mu      sync.Mutex
	wmu     sync.Mutex
	tunFile *os.File
	nat     atomic.Pointer[udpnat.Manager]
	epoch   atomic.Uint64
	running atomic.Bool
	us      atomic.Pointer[ustack.Stack]
	w       atomic.Pointer[tun.Writer]
}

var GlobalTun = &CustomStack{}

var onUnexpectedStop atomic.Pointer[func()]

func SetOnUnexpectedStop(f func()) {
	if f == nil {
		onUnexpectedStop.Store(nil)
		return
	}
	onUnexpectedStop.Store(&f)
}

func (s *CustomStack) Start(tunFd int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, m := s.stopLocked()
	s.FinishStop(u, m)

	_ = syscall.SetNonblock(tunFd, true)
	s.tunFile = os.NewFile(uintptr(tunFd), "tun")
	f := s.tunFile
	epoch := s.epoch.Add(1)
	fw := tun.NewFaultWindow()
	s.w.Store(tun.NewWriter(f, tun.WQueue, &s.wmu, func(pkt []byte) { s.writeOut(f, pkt, epoch, &fw) }))
	s.us.Store(s.newTCPStack(f, epoch))
	s.nat.Store(udpnat.New())
	s.running.Store(true)
	protect.SetRequired(true)

	go s.readTunLoop(s.tunFile, epoch)
	return nil
}

func (s *CustomStack) newTCPStack(f *os.File, epoch uint64) *ustack.Stack {
	return ustack.New(ustack.Config{
		Send:     func(pkt []byte, pooled *[]byte) { s.send(f, pkt, pooled) },
		Alive:    func() bool { return s.epoch.Load() == epoch },
		LateBind: shouldLateBind,
		DialLate: dialForLateBind,
		Handle:   handleTCPConn,
	})
}

func (s *CustomStack) StopAndRelease() (u *ustack.Stack, m *udpnat.Manager) {
	s.mu.Lock()
	u, m = s.stopLocked()
	s.mu.Unlock()
	return u, m
}

func (s *CustomStack) FinishStop(u *ustack.Stack, m *udpnat.Manager) {
	if u != nil {
		u.Close()
	}
	if m != nil {
		m.ClearAll()
	}
}

func (s *CustomStack) IsRunning() bool { return s.running.Load() }

func (s *CustomStack) ResetUDP() {
	if m := s.nat.Load(); m != nil {
		m.ClearAll()
	}
}

func (s *CustomStack) ResetUDPIdle(max int, minIdleSec int64) int {
	if m := s.nat.Load(); m != nil {
		return m.EvictIdle(max, minIdleSec)
	}
	return 0
}

func (s *CustomStack) stopLocked() (u *ustack.Stack, m *udpnat.Manager) {
	if !s.running.CompareAndSwap(true, false) {
		return nil, nil
	}
	s.epoch.Add(1)
	protect.SetRequired(false)
	if w := s.w.Swap(nil); w != nil {
		w.Shutdown()
	}
	if s.tunFile != nil {
		_ = s.tunFile.Close()
		s.tunFile = nil
	}
	u = s.us.Swap(nil)
	m = s.nat.Swap(nil)
	return u, m
}

func (s *CustomStack) readTunLoop(tunFile *os.File, epoch uint64) {
	rd := tun.NewReader(tunFile, tun.Batch)
	for s.epoch.Load() == epoch {
		n, err := rd.Read()
		if s.epoch.Load() != epoch {
			return
		}
		for i := 0; i < n; i++ {
			if s.epoch.Load() != epoch {
				return
			}
			s.dispatch(tunFile, rd.Pkt(i))
		}
		if err != nil {
			if s.epoch.Load() == epoch {
				s.handleUnexpectedTunDeath(epoch)
			}
			return
		}
	}
}

func (s *CustomStack) dispatch(tunFile *os.File, pkt []byte) {
	v, ok := tun.Parse(pkt)
	if !ok {
		return
	}
	switch v.Proto {
	case 6:
		s.handleTCP(v)
	case 17:
		s.handleUDP(tunFile, v)
	case 1, 58:
		s.handleICMP(tunFile, v)
	}
}

func (s *CustomStack) handleUnexpectedTunDeath(epoch uint64) {
	s.mu.Lock()
	if s.epoch.Load() != epoch {
		s.mu.Unlock()
		return
	}
	u, m := s.stopLocked()
	cb := onUnexpectedStop.Load()
	s.mu.Unlock()
	s.FinishStop(u, m)
	if cb != nil {
		go (*cb)()
	}
}

func (s *CustomStack) writeOut(tf *os.File, pkt []byte, epoch uint64, fw *tun.FaultWindow) {
	if fw == nil || s.epoch.Load() != epoch {
		return
	}
	err := writeTUNPacketFn(tf, pkt)
	if s.epoch.Load() != epoch {
		return
	}
	if err == nil {
		fw.RecordSuccess()
		return
	}
	if tun.FaultKind(err) == tun.FaultPeerGone || fw.RecordFault(time.Now()) {
		go s.handleUnexpectedTunDeath(epoch)
		return
	}
	s.wmu.Unlock()
	tunWriteSleep(tun.TransientBackoff)
	s.wmu.Lock()
	if s.epoch.Load() != epoch {
		return
	}
	err = writeTUNPacketFn(tf, pkt)
	if s.epoch.Load() != epoch {
		return
	}
	if err == nil {
		fw.RecordSuccess()
		return
	}
	if tun.FaultKind(err) == tun.FaultPeerGone || fw.RecordFault(time.Now()) {
		go s.handleUnexpectedTunDeath(epoch)
	}
}

var (
	tunWriteSleep    = time.Sleep
	writeTUNPacketFn = tun.WritePacket
)

func (s *CustomStack) send(tf *os.File, pkt []byte, pooled *[]byte) {
	p := tun.Packet{Pkt: pkt, Pooled: pooled}
	if w := s.w.Load(); w != nil && w.File() == tf {
		w.Enqueue(p)
		return
	}
	if s.running.Load() {
		// A live generation that is not tf's: tf is stale, drop the frame.
		p.Release()
		return
	}
	// No live generation (tests, or a send racing Stop). Write the frame
	// without consulting the fault window: there is no generation to kill.
	s.wmu.Lock()
	_ = writeTUNPacketFn(tf, pkt)
	s.wmu.Unlock()
	p.Release()
}

func (s *CustomStack) handleTCP(v tun.View) {
	if len(v.Pkt) < v.L3+20 {
		return
	}
	if u := s.us.Load(); u != nil {
		u.Inject(v)
	}
}

func (s *CustomStack) handleUDP(tunFile *os.File, v tun.View) {
	udp := v.Pkt[v.L3:]
	dp, udpLen := binary.BigEndian.Uint16(udp[2:4]), int(binary.BigEndian.Uint16(udp[4:6]))
	if dp == 853 || udpLen < 8 || udpLen > len(udp) {
		return
	}
	src := netip.AddrPortFrom(v.Addr(0), binary.BigEndian.Uint16(udp[0:2]))
	dst := netip.AddrPortFrom(v.Addr(1), dp)
	payload := udp[8:udpLen]
	if dp == 53 {
		dns.Resolve(context.Background(), payload, func(r []byte) { s.inject(tunFile, dst, src, r) })
		return
	}
	if m := s.nat.Load(); m != nil {
		if m.ForwardPacket(src, dst, payload, func(r []byte, from netip.AddrPort) { s.inject(tunFile, from, src, r) }) {
			s.portUnreachable(tunFile, v)
		}
	}
}

func (s *CustomStack) inject(tf *os.File, src, dst netip.AddrPort, payload []byte) {
	writeUDP(s, tf, src, dst, payload)
}

func writeUDP(s *CustomStack, tunFile *os.File, src, dst netip.AddrPort, payload []byte) {
	hl := 20
	if src.Addr().Is6() {
		hl = 40
	}
	udpLen := 8 + len(payload)
	if hl+udpLen > 65535 {
		return
	}
	var pkt []byte
	var pooled *[]byte
	if hl+udpLen <= 2048 {
		pooled = tun.BufPool.Get().(*[]byte)
		pkt = (*pooled)[:hl+udpLen]
	} else {
		pkt = make([]byte, hl+udpLen)
	}
	clear(pkt[:hl+8])
	if hl == 20 {
		pkt[0], pkt[8], pkt[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(pkt[2:4], uint16(hl+udpLen))
		tun.PutAddr(pkt[12:16], src.Addr())
		tun.PutAddr(pkt[16:20], dst.Addr())
		binary.BigEndian.PutUint16(pkt[10:12], tun.CsumFold(tun.CsumAdd(0, pkt[:20])))
	} else {
		pkt[0], pkt[6], pkt[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
		tun.PutAddr(pkt[8:24], src.Addr())
		tun.PutAddr(pkt[24:40], dst.Addr())
	}
	udp := pkt[hl:]
	binary.BigEndian.PutUint16(udp[0:2], src.Port())
	binary.BigEndian.PutUint16(udp[2:4], dst.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	alen := 4
	if hl == 40 {
		alen = 16
	}
	sum := tun.CsumFold(tun.CsumAdd(tun.CsumAdd(tun.CsumAdd(uint32(17+udpLen), pkt[hl-2*alen:hl-alen]), pkt[hl-alen:hl]), udp))
	if sum == 0 {
		sum = 0xFFFF
	}
	binary.BigEndian.PutUint16(udp[6:8], sum)
	s.send(tunFile, pkt, pooled)
}
