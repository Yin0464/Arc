package ustack

import (
	"arc/core/internal/engine/tun"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	usRcvBuf      = 128 << 10
	usSndBuf      = 128 << 10
	usDefaultMSS  = 1380
	usDefaultMSS6 = 1360
	usMinMSS      = 256
	usRTOMin      = 200 * time.Millisecond
	usRTOMax      = 60 * time.Second
	usMaxRexmit   = 15
	usTick        = 50 * time.Millisecond
	usIdleTick    = 30 * time.Second
	usTimeWait    = 2 * time.Second
	usConnIdle    = 30 * time.Minute
	usRcvWScale   = 7
	usMaxOOOSegs  = 32
	usMaxOOOBytes = 64 << 10
	usInitCwndMSS = 10
	usDelAck      = 40 * time.Millisecond
	usDelAckSegs  = 2
)

const (
	stSynRcvd uint8 = iota
	stEstablished
	stCloseWait
	stLastAck
	stFinWait1
	stFinWait2
	stClosing
	stTimeWait
	stClosed
)

type tcpKey struct {
	remote netip.AddrPort
	local  netip.AddrPort
}

type sackBlk struct{ start, end uint32 }

type seg struct {
	seq     uint32
	data    []byte
	fin     bool
	sent    time.Time
	retries int
	sacked  bool
	box     *[]byte // pooled backing of data, returned once fully acked
}

func (s *seg) free() {
	if s.box != nil {
		tun.BufPool.Put(s.box)
		s.box = nil
	}
}

type oooSeg struct {
	seq  uint32
	data []byte
	fin  bool
}

// Config wires a Stack to its owner. Send writes one frame to the TUN; Alive
// reports whether the owning TUN generation is still current; LateBind picks
// destinations whose SYN-ACK waits for a successful DialLate; Handle takes an
// established connection together with its late-bound upstream, if any.
type Config struct {
	Send     func(pkt []byte, pooled *[]byte)
	Alive    func() bool
	LateBind func(local netip.AddrPort) bool
	DialLate func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	Handle   func(c net.Conn, dst netip.AddrPort, upstream net.Conn)
}

// Stack is the userspace TCP endpoint terminating every TUN TCP flow.
type Stack struct {
	cfg    Config
	mu     sync.Mutex
	conns  map[tcpKey]*tcpConn
	closed atomic.Bool
	stopCh chan struct{}
	kickCh chan struct{}
	fast   atomic.Bool
}

func New(cfg Config) *Stack {
	u := &Stack{
		cfg:    cfg,
		conns:  make(map[tcpKey]*tcpConn),
		stopCh: make(chan struct{}),
		kickCh: make(chan struct{}, 1),
	}
	u.fast.Store(true)
	go u.timerLoop()
	return u
}

func (u *Stack) Close() {
	if u.closed.Swap(true) {
		return
	}
	close(u.stopCh)
	u.mu.Lock()
	list := make([]*tcpConn, 0, len(u.conns))
	for _, c := range u.conns {
		list = append(list, c)
	}
	u.conns = nil
	u.mu.Unlock()
	for _, c := range list {
		c.Abort()
	}
}

func (u *Stack) timerLoop() {
	t := time.NewTimer(usTick)
	defer t.Stop()
	for {
		select {
		case <-u.stopCh:
			return
		case <-u.kickCh:
			t.Reset(usTick)
		case <-t.C:
			busy, any := u.onTick()
			switch {
			case busy:
				t.Reset(usTick)
			case any:
				t.Reset(usIdleTick)
			}
		}
	}
}

func (u *Stack) kick() {
	if u == nil {
		return
	}
	if u.fast.Load() {
		return
	}
	if u.fast.CompareAndSwap(false, true) {
		select {
		case u.kickCh <- struct{}{}:
		default:
		}
	}
}

func (u *Stack) onTick() (busy, any bool) {
	now := time.Now()
	u.fast.Store(false)
	u.mu.Lock()
	list := make([]*tcpConn, 0, len(u.conns))
	for _, c := range u.conns {
		list = append(list, c)
	}
	u.mu.Unlock()
	for _, c := range list {
		if c.onTick(now) {
			busy = true
		}
	}
	if busy {
		u.fast.Store(true)
	}
	return busy, len(list) > 0
}

func (u *Stack) remove(c *tcpConn) {
	u.mu.Lock()
	if u.conns != nil && u.conns[c.key] == c {
		delete(u.conns, c.key)
	}
	u.mu.Unlock()
}

func (u *Stack) Inject(v tun.View) {
	if u.closed.Load() {
		return
	}
	if v.Proto != 6 || len(v.Pkt) < v.L3+20 {
		return
	}
	tcp := v.Pkt[v.L3:]
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || doff > len(tcp) {
		return
	}
	src := netip.AddrPortFrom(v.Addr(0), binary.BigEndian.Uint16(tcp[0:2]))
	dst := netip.AddrPortFrom(v.Addr(1), binary.BigEndian.Uint16(tcp[2:4]))
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	flags := tcp[13]
	wnd := binary.BigEndian.Uint16(tcp[14:16])
	payload := tcp[doff:]
	opts := tcp[20:doff]
	key := tcpKey{remote: src, local: dst}
	fam := v.Fam

	if flags&0x04 != 0 {
		u.mu.Lock()
		c := u.conns[key]
		u.mu.Unlock()
		if c != nil {
			c.Abort()
		}
		return
	}

	if flags&0x02 != 0 {
		if flags&0x10 != 0 {
			return
		}
		u.handleSYN(key, fam, seq, wnd, opts, dst.Port())
		return
	}

	u.mu.Lock()
	c := u.conns[key]
	u.mu.Unlock()
	if c == nil {
		if flags&0x10 != 0 || len(payload) > 0 || flags&0x01 != 0 {
			u.sendRST(fam, dst, src, ack, seq+uint32(len(payload)))
		}
		return
	}
	c.handleSeg(seq, ack, flags, wnd, payload, opts)
}

func (u *Stack) handleSYN(key tcpKey, fam int, isn uint32, wnd uint16, opts []byte, dport uint16) {
	if dport == 853 {
		u.sendRST(fam, key.local, key.remote, 0, isn+1)
		return
	}
	u.mu.Lock()
	if u.closed.Load() || u.conns == nil {
		u.mu.Unlock()
		return
	}
	if old := u.conns[key]; old != nil {
		u.mu.Unlock()
		old.mu.Lock()
		takeover := false
		switch {
		case old.state == stSynRcvd && !old.latePending:
			old.sendSynAckLocked()
		case old.state == stClosed:
			// Closed, its async remove not yet run: the slot is free.
			takeover = true
		case old.state == stTimeWait && seqGT(isn, old.rcvNxt):
			// RFC 1122 4.2.2.13: a new SYN above the old sequence space may
			// reopen a connection in TIME-WAIT.
			old.forceCloseLocked()
			takeover = true
		case old.state != stSynRcvd:
			// RFC 9293 3.10.7.4: a SYN in a synchronized state gets a
			// challenge ACK, so a peer that lost the old connection resets it.
			old.sendAckLocked()
		}
		old.mu.Unlock()
		if !takeover {
			return
		}
		u.mu.Lock()
		if u.closed.Load() || u.conns == nil {
			u.mu.Unlock()
			return
		}
		if cur := u.conns[key]; cur != nil && cur != old {
			u.mu.Unlock()
			return
		}
	}
	iss := newISS()
	mss, sackOK, peerWS, peerWSOk := parseSynOptsFam(opts, fam)
	rcvWS := uint8(0)
	sndWS := uint8(0)
	wscaleOK := false
	if peerWSOk {
		wscaleOK = true
		rcvWS = usRcvWScale
		sndWS = peerWS // parseSynOptsFam caps it at 14
	}
	sndWnd := uint32(wnd)
	if wscaleOK {
		sndWnd = uint32(wnd) << sndWS
	}
	initCwnd := uint32(usInitCwndMSS * mss)
	c := &tcpConn{
		st:        u,
		key:       key,
		fam:       fam,
		state:     stSynRcvd,
		iss:       iss,
		irs:       isn,
		sndUna:    iss,
		sndNxt:    iss + 1,
		sndWnd:    sndWnd,
		rcvNxt:    isn + 1,
		rcvWnd:    usRcvBuf,
		mss:       mss,
		sackOK:    sackOK,
		wscaleOK:  wscaleOK,
		sndWscale: sndWS,
		rcvWscale: rcvWS,
		cwnd:      initCwnd,
		ssthresh:  usSndBuf,
		rwait:     make(chan struct{}, 1),
		swait:     make(chan struct{}, 1),
		lastRx:    time.Now(),
		rto:       usRTOMin,
		localAP:   key.local,
		remoteAP:  key.remote,
	}
	u.conns[key] = c
	u.mu.Unlock()
	if u.cfg.LateBind(key.local) {
		c.mu.Lock()
		c.latePending = true
		c.mu.Unlock()
		go c.lateBindAndSynAck()
		return
	}
	c.mu.Lock()
	c.sendSynAckLocked()
	c.mu.Unlock()
}

func (c *tcpConn) lateBindAndSynAck() {
	dst := c.localAP
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	r, err := c.st.cfg.DialLate(ctx, dst)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != stSynRcvd {
		if r != nil {
			_ = r.Close()
		}
		return
	}
	if err != nil || r == nil {
		if r != nil {
			_ = r.Close()
		}
		c.sendRSTLocked()
		c.forceCloseLocked()
		return
	}
	c.preDial = r
	c.latePending = false
	c.sendSynAckLocked()
}

func famMSS(fam int) int {
	if fam == 1 {
		return usDefaultMSS6
	}
	return usDefaultMSS
}

func parseSynOptsFam(opts []byte, fam int) (mss int, sackOK bool, wscale uint8, wscaleOK bool) {
	maxMSS := famMSS(fam)
	mss = maxMSS
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		switch kind {
		case 2:
			if l == 4 {
				mss = min(max(int(binary.BigEndian.Uint16(opts[i+2:])), usMinMSS), maxMSS)
			}
		case 3:
			if l == 3 {
				wscale = min(opts[i+2], 14)
				wscaleOK = true
			}
		case 4:
			sackOK = true
		}
		i += l
	}
	return
}

func newISS() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

func (u *Stack) sendRST(fam int, src, dst netip.AddrPort, seq, ack uint32) {
	flags := byte(0x04)
	if ack != 0 {
		flags |= 0x10
	}
	u.emitTCP(fam, src, dst, seq, ack, flags, 0, nil, nil)
}

func (u *Stack) emitTCP(fam int, src, dst netip.AddrPort, seq, ack uint32, flags byte, wnd uint16, opts, payload []byte) {
	if u.closed.Load() {
		return
	}
	hl := 20
	if fam == 1 {
		hl = 40
	}
	doff := 20 + len(opts)
	if doff%4 != 0 {
		pad := 4 - doff%4
		opts = append(append([]byte(nil), opts...), make([]byte, pad)...)
		doff += pad
	}
	tcpLen := doff + len(payload)
	need := hl + tcpLen
	var pkt []byte
	var pooled *[]byte
	if need <= 2048 {
		pooled = tun.BufPool.Get().(*[]byte)
		pkt = (*pooled)[:need]
	} else {
		pkt = make([]byte, need)
	}
	clear(pkt[:hl+doff])
	if fam == 0 {
		pkt[0], pkt[8], pkt[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(pkt[2:4], uint16(hl+tcpLen))
		tun.PutAddr(pkt[12:16], src.Addr())
		tun.PutAddr(pkt[16:20], dst.Addr())
		binary.BigEndian.PutUint16(pkt[10:12], tun.CsumFold(tun.CsumAdd(0, pkt[:20])))
	} else {
		pkt[0], pkt[6], pkt[7] = 0x60, 6, 64
		binary.BigEndian.PutUint16(pkt[4:6], uint16(tcpLen))
		tun.PutAddr(pkt[8:24], src.Addr())
		tun.PutAddr(pkt[24:40], dst.Addr())
	}
	tcp := pkt[hl:]
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = byte(doff/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], wnd)
	if len(opts) > 0 {
		copy(tcp[20:], opts)
	}
	if len(payload) > 0 {
		copy(tcp[doff:], payload)
	}
	alen := 4
	if fam == 1 {
		alen = 16
	}
	sum := tun.CsumFold(tun.CsumAdd(tun.CsumAdd(tun.CsumAdd(uint32(6+tcpLen), pkt[hl-2*alen:hl-alen]), pkt[hl-alen:hl]), tcp))
	binary.BigEndian.PutUint16(tcp[16:18], sum)
	u.cfg.Send(pkt, pooled)
}

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }

func seqGT(a, b uint32) bool { return int32(a-b) > 0 }

func seqGE(a, b uint32) bool { return int32(a-b) >= 0 }

type tcpConn struct {
	st       *Stack
	key      tcpKey
	fam      int
	localAP  netip.AddrPort
	remoteAP netip.AddrPort

	mu     sync.Mutex
	state  uint8
	iss    uint32
	irs    uint32
	sndUna uint32
	sndNxt uint32
	sndWnd uint32
	rcvNxt uint32
	rcvWnd uint32
	mss    int
	sackOK bool

	wscaleOK  bool
	sndWscale uint8
	rcvWscale uint8

	cwnd     uint32
	ssthresh uint32
	dupAcks  int
	inFast   bool
	recover  uint32

	rbuf    []byte
	ooo     []oooSeg
	unacked []seg
	pending []byte
	wantFin bool
	finSent bool
	finSeq  uint32

	rwait chan struct{}
	swait chan struct{}

	rdead atomic.Pointer[time.Time]
	wdead atomic.Pointer[time.Time]

	lastRx time.Time
	rto    time.Duration
	srtt   time.Duration
	rttvar time.Duration
	rttOK  bool
	handed bool
	closed bool

	delayedAck  bool
	delAckAt    time.Time
	delAckBytes uint32
	timeWait    time.Time

	latePending bool
	preDial     net.Conn
	probeAt     time.Time
}

func (c *tcpConn) notify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (c *tcpConn) advWnd() uint16 {
	w := c.rcvWnd
	if c.wscaleOK {
		w >>= c.rcvWscale
	}
	return uint16(min(w, 65535))
}

func (c *tcpConn) synAckOpts() []byte {
	m := famMSS(c.fam)
	opts := []byte{
		2, 4, byte(m >> 8), byte(m & 0xff),
		1, 1,
		4, 2,
	}
	if c.wscaleOK {
		opts = append(opts, 3, 3, c.rcvWscale)
	}
	return opts
}

func (c *tcpConn) sendSynAckLocked() {
	opts := c.synAckOpts()
	c.st.emitTCP(c.fam, c.localAP, c.remoteAP, c.iss, c.rcvNxt, 0x12, c.advWnd(), opts, nil)
	c.unacked = []seg{{seq: c.iss, sent: time.Now()}}
	c.st.kick()
}

func (c *tcpConn) handleSeg(seq, ack uint32, flags byte, wnd uint16, payload []byte, opts []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == stClosed {
		return
	}
	c.lastRx = time.Now()
	oldWnd := c.sndWnd
	if c.wscaleOK {
		c.sndWnd = uint32(wnd) << c.sndWscale
	} else {
		c.sndWnd = uint32(wnd)
	}

	if flags&0x10 != 0 {
		c.applyAckLocked(ack, opts, len(payload), flags, oldWnd)
	} else if c.sndWnd > oldWnd {
		c.flushPendingLocked()
	}

	switch c.state {
	case stSynRcvd:
		if flags&0x10 != 0 && ack == c.iss+1 {
			c.sndUna = c.iss + 1
			c.unacked = nil
			c.state = stEstablished
			c.consumePayloadLocked(seq, flags, payload)
			if !c.handed {
				c.handed = true
				dst := c.localAP
				go c.deliver(dst)
			}
		}
	case stEstablished, stCloseWait, stFinWait1, stFinWait2, stClosing, stLastAck:
		c.consumePayloadLocked(seq, flags, payload)
	case stTimeWait:
		if flags&0x10 != 0 {
			c.sendAckLocked()
		}
	}
}

func (c *tcpConn) deliver(dst netip.AddrPort) {
	if !c.st.cfg.Alive() {
		c.Abort()
		return
	}
	c.mu.Lock()
	pre := c.preDial
	c.preDial = nil
	c.mu.Unlock()
	c.st.cfg.Handle(c, dst, pre)
}

func (c *tcpConn) applyAckLocked(ack uint32, opts []byte, payloadLen int, flags byte, oldWnd uint32) {
	if seqGT(ack, c.sndNxt) {
		return
	}
	oldUna := c.sndUna
	if !seqGT(ack, oldUna) {
		// RFC 5681: a duplicate ACK carries no data, does not change the
		// window, is not SYN/FIN, and only counts while data is outstanding.
		if ack == oldUna && c.state != stSynRcvd && payloadLen == 0 && flags&0x03 == 0 &&
			c.sndWnd == oldWnd && c.sndNxt != c.sndUna {
			c.onDupAckLocked()
		}
		c.flushPendingLocked()
		return
	}

	acked := ack - oldUna
	c.sndUna = ack
	kept := c.unacked[:0]
	var sampleRTT time.Duration
	var haveSample bool
	for _, s := range c.unacked {
		end := s.seq + uint32(len(s.data))
		if s.fin {
			end++
		}
		if !seqGT(end, ack) {
			s.free()
			if s.retries == 0 && !haveSample && !s.sent.IsZero() {
				sampleRTT = time.Since(s.sent)
				haveSample = sampleRTT > 0
			}
			continue
		}
		if seqGT(ack, s.seq) && len(s.data) > 0 {
			off := ack - s.seq
			if off < uint32(len(s.data)) {
				s.data = s.data[off:]
				s.seq = ack
				s.sacked = false
				kept = append(kept, s)
			} else if s.fin {
				s.free()
				s.data = nil
				s.seq = ack
				kept = append(kept, s)
			}
		} else {
			kept = append(kept, s)
		}
	}
	c.unacked = kept
	c.applySACKLocked(opts)
	if haveSample {
		c.updateRTTLocked(sampleRTT)
	}
	c.onNewAckLocked(acked, ack)
	c.notify(c.swait)
	c.flushPendingLocked()

	switch c.state {
	case stFinWait1:
		if c.finSent && !seqGT(c.finSeq+1, ack) {
			c.state = stFinWait2
		}
	case stClosing:
		if c.finSent && !seqGT(c.finSeq+1, ack) {
			c.state = stTimeWait
			c.timeWait = time.Now()
			c.st.kick()
		}
	case stLastAck:
		if c.finSent && !seqGT(c.finSeq+1, ack) {
			c.forceCloseLocked()
		}
	}
}

func (c *tcpConn) onNewAckLocked(acked, ack uint32) {
	if acked == 0 {
		return
	}
	if c.inFast {
		if !seqGT(c.recover, ack) {
			c.cwnd = c.ssthresh
			c.inFast = false
			c.dupAcks = 0
		} else {
			if c.cwnd > acked {
				c.cwnd -= acked
			} else {
				c.cwnd = uint32(c.mss)
			}
			c.cwnd += uint32(c.mss)
			c.rexmitFirstUnackedLocked()
		}
		return
	}
	c.dupAcks = 0
	if c.cwnd < c.ssthresh {
		c.cwnd += min(acked, uint32(c.mss))
	} else {
		c.cwnd += max(uint32(c.mss)*uint32(c.mss)/c.cwnd, 1)
	}
	c.cwnd = min(c.cwnd, usSndBuf)
}

func (c *tcpConn) updateRTTLocked(sample time.Duration) {
	sample = max(sample, time.Millisecond)
	if !c.rttOK {
		c.srtt = sample
		c.rttvar = sample / 2
		c.rttOK = true
	} else {
		diff := c.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		c.rttvar = (3*c.rttvar + diff) / 4
		c.srtt = (7*c.srtt + sample) / 8
	}
	c.rto = min(max(c.srtt+4*c.rttvar, usRTOMin), usRTOMax)
}

func (c *tcpConn) onDupAckLocked() {
	c.dupAcks++
	if !c.inFast && c.dupAcks == 3 {
		c.ssthresh = max((c.sndNxt-c.sndUna)/2, uint32(2*c.mss))
		c.cwnd = c.ssthresh + 3*uint32(c.mss)
		c.inFast = true
		c.recover = c.sndNxt
		c.rexmitFirstUnackedLocked()
		return
	}
	if c.inFast {
		c.cwnd = min(c.cwnd+uint32(c.mss), usSndBuf)
		c.flushPendingLocked()
	}
}

// emitSegLocked (re)transmits one unacked segment: the SYN-ACK when it is
// the handshake segment, otherwise ACK plus PSH / FIN as the segment needs.
func (c *tcpConn) emitSegLocked(s *seg) {
	if s.seq == c.iss && len(s.data) == 0 && !s.fin {
		c.st.emitTCP(c.fam, c.localAP, c.remoteAP, s.seq, c.rcvNxt, 0x12, c.advWnd(), c.synAckOpts(), nil)
		return
	}
	flags := byte(0x10)
	if len(s.data) > 0 {
		flags |= 0x08
	}
	if s.fin {
		flags |= 0x01
	}
	c.st.emitTCP(c.fam, c.localAP, c.remoteAP, s.seq, c.rcvNxt, flags, c.advWnd(), nil, s.data)
}

func (c *tcpConn) rexmitFirstUnackedLocked() {
	for i := range c.unacked {
		s := &c.unacked[i]
		if s.sacked {
			continue
		}
		c.emitSegLocked(s)
		s.sent = time.Now()
		s.retries++
		return
	}
}

func (c *tcpConn) applySACKLocked(opts []byte) {
	if !c.sackOK || len(opts) == 0 {
		return
	}
	blks := parseSACK(opts)
	if len(blks) == 0 {
		return
	}
	for i := range c.unacked {
		s := &c.unacked[i]
		end := s.seq + uint32(len(s.data))
		if s.fin {
			end++
		}
		for _, b := range blks {
			if seqGE(s.seq, b.start) && !seqGT(end, b.end) && seqGT(b.end, b.start) {
				s.sacked = true
			}
		}
	}
}

func parseSACK(opts []byte) []sackBlk {
	var out []sackBlk
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		if kind == 5 && l >= 10 && (l-2)%8 == 0 {
			for o := i + 2; o+8 <= i+l; o += 8 {
				out = append(out, sackBlk{
					start: binary.BigEndian.Uint32(opts[o:]),
					end:   binary.BigEndian.Uint32(opts[o+4:]),
				})
			}
		}
		i += l
	}
	return out
}

func (c *tcpConn) consumePayloadLocked(seq uint32, flags byte, payload []byte) {
	gotFIN := flags&0x01 != 0
	if len(payload) == 0 && !gotFIN {
		// An empty segment below rcvNxt (a keep-alive probe, RFC 1122
		// 4.2.3.6) is ACKed; in-window pure ACKs are not.
		if seqLT(seq, c.rcvNxt) {
			c.sendAckLocked()
		}
		return
	}
	if c.state == stCloseWait || c.state == stLastAck || c.state == stTimeWait {
		c.sendAckLocked()
		return
	}

	end := seq + uint32(len(payload))
	if gotFIN {
		end++
	}

	if !seqGT(end, c.rcvNxt) {
		c.sendAckLocked()
		return
	}

	if seqLT(seq, c.rcvNxt) {
		skip := c.rcvNxt - seq
		if int(skip) <= len(payload) {
			payload = payload[skip:]
			seq = c.rcvNxt
		} else {
			payload = nil
			seq = c.rcvNxt
		}
	}

	if seqGT(seq, c.rcvNxt) {
		c.storeOOOLocked(seq, payload, gotFIN)
		c.sendAckLocked()
		return
	}

	winClamped := false
	if len(payload) > 0 {
		room := usRcvBuf - len(c.rbuf)
		if room < len(payload) {
			payload = payload[:max(0, room)]
			gotFIN = false
			winClamped = true
		}
		if len(payload) > 0 {
			c.rbuf = append(c.rbuf, payload...)
			c.rcvNxt += uint32(len(payload))
			c.rcvWnd = uint32(usRcvBuf - len(c.rbuf))
			c.notify(c.rwait)
		}
	}
	finTaken := false
	if gotFIN && seq+uint32(len(payload)) == c.rcvNxt {
		c.rcvNxt++
		finTaken = true
		c.applyPeerFinLocked()
	}
	c.drainOOOLocked()
	// A clamped segment (including a zero-window probe) is ACKed at once so
	// the peer learns the current rcvNxt and window.
	if finTaken || len(c.ooo) > 0 || gotFIN || winClamped {
		c.sendAckLocked()
	} else if len(payload) > 0 {
		c.scheduleAckLocked(len(payload), false)
	}
}

func (c *tcpConn) applyPeerFinLocked() {
	switch c.state {
	case stEstablished:
		c.state = stCloseWait
	case stFinWait1:
		c.state = stClosing
	case stFinWait2:
		c.state = stTimeWait
		c.timeWait = time.Now()
		c.st.kick()
	default:
		return
	}
	c.notify(c.rwait)
}

func (c *tcpConn) storeOOOLocked(seq uint32, payload []byte, fin bool) {
	if len(payload) == 0 && !fin {
		return
	}

	total := 0
	for _, s := range c.ooo {
		total += len(s.data)
	}
	if len(c.ooo) >= usMaxOOOSegs || total+len(payload) > usMaxOOOBytes {
		return
	}
	end := seq + uint32(len(payload))

	newData := append([]byte(nil), payload...)
	newFin := fin
	// Fresh backing: out := c.ooo[:0] aliases the slice this loop still reads.
	out := make([]oooSeg, 0, len(c.ooo)+1)
	inserted := false
	for _, s := range c.ooo {
		sEnd := s.seq + uint32(len(s.data))

		if !seqGT(sEnd, seq) {
			out = append(out, s)
			continue
		}

		if !seqGT(end, s.seq) {
			if !inserted {
				out = append(out, oooSeg{seq: seq, data: newData, fin: newFin})
				inserted = true
			}
			out = append(out, s)
			continue
		}

		if seqLT(s.seq, seq) {
			prefix := s.data[:seq-s.seq]
			newData = append(append([]byte(nil), prefix...), newData...)
			seq = s.seq
		}
		if seqGT(sEnd, end) {
			suffix := s.data[end-s.seq:]
			newData = append(newData, suffix...)
			end = sEnd
		}
		if s.fin {
			newFin = true
		}
	}
	if !inserted {
		out = append(out, oooSeg{seq: seq, data: newData, fin: newFin})
	}
	c.ooo = out
}

func (c *tcpConn) drainOOOLocked() {
	for len(c.ooo) > 0 {
		s := c.ooo[0]
		if seqGT(s.seq, c.rcvNxt) {
			return
		}
		c.ooo = c.ooo[1:]
		payload := s.data
		fin := s.fin
		if seqLT(s.seq, c.rcvNxt) {
			skip := c.rcvNxt - s.seq
			if int(skip) >= len(payload) {
				if fin && s.seq+uint32(len(s.data)) == c.rcvNxt {
					payload = nil
				} else {
					continue
				}
			} else {
				payload = payload[skip:]
			}
		}
		if len(payload) > 0 {
			room := usRcvBuf - len(c.rbuf)
			if room <= 0 {
				c.ooo = append([]oooSeg{{seq: c.rcvNxt, data: payload, fin: fin}}, c.ooo...)
				return
			}
			if room < len(payload) {
				rest := payload[room:]
				payload = payload[:room]
				c.ooo = append([]oooSeg{{seq: c.rcvNxt + uint32(len(payload)), data: rest, fin: fin}}, c.ooo...)
				fin = false
			}
			c.rbuf = append(c.rbuf, payload...)
			c.rcvNxt += uint32(len(payload))
			c.rcvWnd = uint32(usRcvBuf - len(c.rbuf))
			c.notify(c.rwait)
		}
		if fin {
			c.rcvNxt++
			c.applyPeerFinLocked()
			c.ooo = nil
			return
		}
	}
}

func (c *tcpConn) sackOptionLocked() []byte {
	if !c.sackOK || len(c.ooo) == 0 {
		return nil
	}
	n := min(len(c.ooo), 3)
	opts := make([]byte, 2+n*8)
	opts[0], opts[1] = 5, byte(2+n*8)
	for i := 0; i < n; i++ {
		s := c.ooo[i]
		end := s.seq + uint32(len(s.data))
		if s.fin {
			end++
		}
		o := 2 + i*8
		binary.BigEndian.PutUint32(opts[o:], s.seq)
		binary.BigEndian.PutUint32(opts[o+4:], end)
	}
	return opts
}

func (c *tcpConn) sendAckLocked() {
	c.delayedAck = false
	c.delAckBytes = 0
	c.delAckAt = time.Time{}
	c.st.emitTCP(c.fam, c.localAP, c.remoteAP, c.sndNxt, c.rcvNxt, 0x10, c.advWnd(), c.sackOptionLocked(), nil)
}

func (c *tcpConn) scheduleAckLocked(nbytes int, immediate bool) {
	if immediate || nbytes <= 0 {
		c.sendAckLocked()
		return
	}
	c.delAckBytes += uint32(nbytes)
	if c.delAckBytes >= uint32(usDelAckSegs*c.mss) {
		c.sendAckLocked()
		return
	}
	if !c.delayedAck {
		c.delayedAck = true
		c.delAckAt = time.Now().Add(usDelAck)
		c.st.kick()
	}
}

func (c *tcpConn) sendDataLocked(data []byte, box *[]byte, fin bool) {
	seq := c.sndNxt
	c.delayedAck = false
	c.delAckBytes = 0
	s := seg{seq: seq, data: data, fin: fin, sent: time.Now(), box: box}
	c.emitSegLocked(&s)
	c.sndNxt += uint32(len(data))
	if fin {
		c.finSent = true
		c.finSeq = seq + uint32(len(data))
		c.sndNxt++
	}
	c.unacked = append(c.unacked, s)
	c.st.kick()
}

func (c *tcpConn) flushPendingLocked() {
	for {
		inFlight := int(c.sndNxt - c.sndUna)
		budget := min(max(0, int(c.sndWnd)-inFlight), max(0, int(c.cwnd)-inFlight), c.mss, usSndBuf-inFlight)

		fin := false
		var chunk []byte
		var box *[]byte
		if len(c.pending) > 0 {
			if budget <= 0 {
				return
			}
			n := min(budget, len(c.pending))
			box = tun.BufPool.Get().(*[]byte) // n <= mss < 2048
			chunk = append((*box)[:0], c.pending[:n]...)
			if n == len(c.pending) {
				c.pending = c.pending[:0]
			} else {
				c.pending = c.pending[n:]
			}
			if len(c.pending) == 0 && c.wantFin && !c.finSent {
				fin = true
			}
		} else if c.wantFin && !c.finSent {
			fin = true
		} else {
			return
		}
		c.sendDataLocked(chunk, box, fin)
		if fin {
			switch c.state {
			case stEstablished:
				c.state = stFinWait1
			case stCloseWait:
				c.state = stLastAck
			}
			return
		}
	}
}

func (c *tcpConn) onTick(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tickLocked(now)
	return c.needsTimerLocked()
}

func (c *tcpConn) needsTimerLocked() bool {
	if c.state == stClosed {
		return false
	}
	return c.state == stTimeWait || c.state == stSynRcvd || len(c.unacked) > 0 || c.delayedAck ||
		(len(c.pending) > 0 && c.sndWnd > 0) || (c.wantFin && !c.finSent)
}

func (c *tcpConn) tickLocked(now time.Time) {
	if c.state == stClosed {
		return
	}
	if c.state == stTimeWait {
		if now.Sub(c.timeWait) >= usTimeWait {
			c.forceCloseLocked()
		}
		return
	}
	if now.Sub(c.lastRx) > usConnIdle {
		c.sendRSTLocked()
		c.forceCloseLocked()
		return
	}
	if c.delayedAck && !c.delAckAt.IsZero() && !now.Before(c.delAckAt) {
		c.sendAckLocked()
	}
	// RFC 9293 3.8.6.1: while the peer's window is zero, an ACK below sndUna
	// makes it re-advertise the window, so a lost window update cannot stall.
	if c.sndWnd == 0 && len(c.unacked) == 0 && len(c.pending) > 0 {
		if c.probeAt.IsZero() {
			c.probeAt = now.Add(c.rto)
		} else if !now.Before(c.probeAt) {
			c.st.emitTCP(c.fam, c.localAP, c.remoteAP, c.sndUna-1, c.rcvNxt, 0x10, c.advWnd(), nil, nil)
			c.probeAt = now.Add(usIdleTick)
		}
	} else {
		c.probeAt = time.Time{}
	}

	for i := range c.unacked {
		s := &c.unacked[i]
		if s.sacked {
			continue
		}
		if now.Sub(s.sent) < c.rto {
			break
		}
		if s.retries >= usMaxRexmit {
			c.sendRSTLocked()
			c.forceCloseLocked()
			return
		}
		c.emitSegLocked(s)
		s.retries++
		s.sent = now
		c.rto = min(c.rto*2, usRTOMax)
		c.ssthresh = max((c.sndNxt-c.sndUna)/2, uint32(2*c.mss))
		c.cwnd = uint32(c.mss)
		c.inFast = false
		c.dupAcks = 0
		break
	}
}

func (c *tcpConn) sendRSTLocked() {
	c.st.emitTCP(c.fam, c.localAP, c.remoteAP, c.sndNxt, c.rcvNxt, 0x14, 0, nil, nil)
}

func (c *tcpConn) forceCloseLocked() {
	if c.state == stClosed {
		return
	}
	if c.preDial != nil {
		_ = c.preDial.Close()
		c.preDial = nil
	}
	c.state = stClosed
	c.closed = true
	c.pending = nil
	for i := range c.unacked {
		c.unacked[i].free()
	}
	c.unacked = nil
	c.ooo = nil
	c.delayedAck = false
	c.delAckBytes = 0
	c.delAckAt = time.Time{}
	c.notify(c.rwait)
	c.notify(c.swait)
	go c.st.remove(c)
}

func (c *tcpConn) Abort() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == stClosed {
		return
	}
	c.sendRSTLocked()
	c.forceCloseLocked()
}

func (c *tcpConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.rbuf) > 0 {
			n := copy(b, c.rbuf)
			if n == len(c.rbuf) {
				c.rbuf = c.rbuf[:0]
			} else {
				c.rbuf = c.rbuf[n:]
			}
			oldWnd := c.rcvWnd
			oldNxt := c.rcvNxt
			c.rcvWnd = uint32(usRcvBuf - len(c.rbuf))
			c.drainOOOLocked()
			mss := uint32(c.mss)
			opened := c.rcvWnd > oldWnd && ((oldWnd < mss && c.rcvWnd >= mss) || (c.rcvWnd-oldWnd) >= mss)
			if opened || c.rcvNxt != oldNxt {
				c.sendAckLocked()
			}
			c.mu.Unlock()
			return n, nil
		}
		readableClosed := c.state == stCloseWait || c.state == stLastAck || c.state == stClosed ||
			c.state == stTimeWait || c.state == stClosing
		if readableClosed {
			if c.state == stClosed {
				c.mu.Unlock()
				return 0, net.ErrClosed
			}
			c.mu.Unlock()
			return 0, io.EOF
		}
		c.mu.Unlock()

		var deadline time.Time
		if p := c.rdead.Load(); p != nil {
			deadline = *p
		}
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(d)
			select {
			case <-c.rwait:
				timer.Stop()
			case <-timer.C:
				return 0, os.ErrDeadlineExceeded
			}
		} else {
			<-c.rwait
		}
	}
}

func (c *tcpConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	sent := 0
	for sent < len(b) {
		c.mu.Lock()
		if c.state == stClosed || c.wantFin || c.finSent ||
			c.state == stFinWait1 || c.state == stFinWait2 || c.state == stClosing ||
			c.state == stLastAck || c.state == stTimeWait {
			c.mu.Unlock()
			if sent > 0 {
				return sent, nil
			}
			return 0, net.ErrClosed
		}
		room := usSndBuf - len(c.pending) - int(c.sndNxt-c.sndUna)
		if room > 0 {
			n := min(room, len(b)-sent)
			c.pending = append(c.pending, b[sent:sent+n]...)
			c.st.kick()
			sent += n
			c.flushPendingLocked()
			c.mu.Unlock()
			continue
		}
		c.mu.Unlock()
		var deadline time.Time
		if p := c.wdead.Load(); p != nil {
			deadline = *p
		}
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				if sent > 0 {
					return sent, nil
				}
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(d)
			select {
			case <-c.swait:
				timer.Stop()
			case <-timer.C:
				if sent > 0 {
					return sent, nil
				}
				return 0, os.ErrDeadlineExceeded
			}
		} else {
			<-c.swait
		}
	}
	return sent, nil
}

func (c *tcpConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == stClosed {
		return net.ErrClosed
	}
	if c.wantFin || c.finSent {
		return nil
	}
	c.wantFin = true
	c.flushPendingLocked()
	c.notify(c.swait)
	return nil
}

func (c *tcpConn) Close() error {
	c.mu.Lock()
	if c.state == stClosed {
		c.mu.Unlock()
		return nil
	}
	if !c.wantFin && !c.finSent {
		c.wantFin = true
		c.flushPendingLocked()
		c.notify(c.swait)
	}

	if c.state == stSynRcvd {
		c.sendRSTLocked()
		c.forceCloseLocked()
	}
	c.mu.Unlock()
	return nil
}

func (c *tcpConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: c.localAP.Addr().AsSlice(), Port: int(c.localAP.Port())}
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: c.remoteAP.Addr().AsSlice(), Port: int(c.remoteAP.Port())}
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	c.rdead.Store(&t)
	c.notify(c.rwait)
	return nil
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	c.wdead.Store(&t)
	c.notify(c.swait)
	return nil
}

var (
	_ net.Conn                        = (*tcpConn)(nil)
	_ interface{ CloseWrite() error } = (*tcpConn)(nil)
)
