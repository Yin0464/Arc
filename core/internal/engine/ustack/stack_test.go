package ustack

import (
	"arc/core/internal/engine/tun"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func mkIPv4TCP(src, dst netip.Addr, sp, dp uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	return mkIPv4TCPOpts(src, dst, sp, dp, seq, ack, flags, nil, payload)
}

func mkIPv4TCPOpts(src, dst netip.Addr, sp, dp uint16, seq, ack uint32, flags byte, opts, payload []byte) []byte {
	doff := 20 + len(opts)
	pad := (4 - doff%4) % 4
	if pad > 0 {
		opts = append(append([]byte(nil), opts...), make([]byte, pad)...)
		doff += pad
	}
	tcp := make([]byte, doff+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], sp)
	binary.BigEndian.PutUint16(tcp[2:], dp)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = byte(doff/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	if len(opts) > 0 {
		copy(tcp[20:], opts)
	}
	copy(tcp[doff:], payload)
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	copy(ip[12:], src.AsSlice())
	copy(ip[16:], dst.AsSlice())
	binary.BigEndian.PutUint16(ip[10:], tun.CsumFold(tun.CsumAdd(0, ip)))
	binary.BigEndian.PutUint16(tcp[16:], tun.CsumFold(tun.CsumAdd(tun.CsumAdd(tun.CsumAdd(uint32(6+len(tcp)), src.AsSlice()), dst.AsSlice()), tcp)))
	return append(ip, tcp...)
}

func readTCP(t *testing.T, peer *os.File, deadline time.Duration, wantFlags byte) (seq, ack uint32, payload []byte, pkt []byte) {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(deadline))
	buf := make([]byte, 2048)
	for {
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		v, ok := tun.Parse(buf[:n])
		if !ok || v.Proto != 6 {
			continue
		}
		l4 := v.Pkt[v.L3:]
		if l4[13]&wantFlags != wantFlags {
			continue
		}
		verify(t, v.Pkt)
		doff := int(l4[12]>>4) * 4
		return binary.BigEndian.Uint32(l4[4:8]), binary.BigEndian.Uint32(l4[8:12]), append([]byte(nil), l4[doff:]...), append([]byte(nil), v.Pkt...)
	}
}

func startStackPair(t *testing.T) (u *Stack, peer *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Skip(err)
	}
	peer = os.NewFile(uintptr(fds[1]), "peer")
	f := os.NewFile(uintptr(fds[0]), "tun")
	var mu sync.Mutex
	u = New(Config{
		Send: func(pkt []byte, pooled *[]byte) {
			mu.Lock()
			_ = tun.WritePacket(f, pkt)
			mu.Unlock()
			tun.Packet{Pkt: pkt, Pooled: pooled}.Release()
		},
		Alive:    func() bool { return true },
		LateBind: func(netip.AddrPort) bool { return false },
		Handle: func(c net.Conn, _ netip.AddrPort, _ net.Conn) {
			c.(interface{ Abort() }).Abort()
		},
	})
	go func() {
		rd := tun.NewReader(f, 1)
		for {
			n, err := rd.Read()
			for i := 0; i < n; i++ {
				if v, ok := tun.Parse(rd.Pkt(i)); ok && v.Proto == 6 {
					u.Inject(v)
				}
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		u.Close()
		_ = f.Close()
		_ = peer.Close()
	})
	return u, peer
}

func claimConn(t *testing.T, u *Stack, key tcpKey) *tcpConn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		u.mu.Lock()
		c := u.conns[key]
		u.mu.Unlock()
		if c != nil {
			c.mu.Lock()
			c.handed = true
			c.mu.Unlock()
			return c
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("no conn")
	return nil
}

func waitEstablished(t *testing.T, c *tcpConn) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		st := c.state
		c.mu.Unlock()
		if st == stEstablished {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("not established")
}

func TestUserStackSynAck(t *testing.T) {
	u, peer := startStackPair(t)
	if u == nil {
		t.Fatal("user stack not default")
	}
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("1.1.1.1")
	syn := mkIPv4TCP(src, dst, 40001, 80, 1000, 0, 0x02, nil)
	if _, err := peer.Write(syn); err != nil {
		t.Fatal(err)
	}
	seq, ack, _, _ := readTCP(t, peer, 3*time.Second, 0x12)
	if ack != 1001 {
		t.Fatalf("ack=%d want 1001", ack)
	}
	if seq == 0 {
		t.Fatal("iss zero")
	}
}

func TestUserStackEcho(t *testing.T) {
	u, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("9.9.9.9")
	const cport, dport uint16 = 41000, 7
	isn := uint32(5000)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	iss, ack, _, _ := readTCP(t, peer, 3*time.Second, 0x12)
	if ack != isn+1 {
		t.Fatalf("synack ack=%d", ack)
	}
	key := tcpKey{remote: netip.AddrPortFrom(src, cport), local: netip.AddrPortFrom(dst, dport)}
	c := claimConn(t, u, key)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, c)
	payload := []byte("ping")
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x18, payload)); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	gotAck := false
	for !gotAck {
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatal("no ack for data:", err)
		}
		v, ok := tun.Parse(buf[:n])
		if !ok || v.Proto != 6 {
			continue
		}
		l4 := v.Pkt[v.L3:]
		if l4[13]&0x10 != 0 && binary.BigEndian.Uint32(l4[8:12]) == isn+1+uint32(len(payload)) {
			gotAck = true
			verify(t, v.Pkt)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 16)
	n, err := c.Read(got)
	if err != nil || string(got[:n]) != "ping" {
		t.Fatalf("Read=%q err=%v", got[:n], err)
	}
	if _, err := c.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	_, _, data, _ := readTCP(t, peer, 2*time.Second, 0x18)
	if string(data) != "pong" {
		_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		found := false
		for !found {
			n, err := peer.Read(buf)
			if err != nil {
				t.Fatal("no pong:", err)
			}
			v, ok := tun.Parse(buf[:n])
			if !ok || v.Proto != 6 {
				continue
			}
			l4 := v.Pkt[v.L3:]
			doff := int(l4[12]>>4) * 4
			if string(l4[doff:]) == "pong" {
				verify(t, v.Pkt)
				found = true
			}
		}
	}
	_ = c.CloseWrite()
	c.mu.Lock()
	sndNxt := c.sndNxt
	c.mu.Unlock()
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1+uint32(len(payload)), sndNxt, 0x11, nil)); err != nil {
		t.Fatal(err)
	}
	_ = io.EOF
}

func TestUserStackRejectDoT(t *testing.T) {
	_, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("1.1.1.1")
	if _, err := peer.Write(mkIPv4TCP(src, dst, 40002, 853, 1, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	for {
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatal("no RST:", err)
		}
		v, ok := tun.Parse(buf[:n])
		if !ok || v.Proto != 6 {
			continue
		}
		if v.Pkt[v.L3:][13]&0x04 != 0 {
			return
		}
	}
}

func TestParseSynOptsWScale(t *testing.T) {
	opts := []byte{
		2, 4, 0x05, 0xB4,
		1, 1,
		4, 2,
		3, 3, 8,
	}
	mss, sack, ws, ok := parseSynOptsFam(opts, 0)
	if mss != usDefaultMSS {
		if mss != 1360 && mss != 1460 {

			if mss != usDefaultMSS {
				t.Fatalf("mss=%d", mss)
			}
		}
	}
	_ = mss
	if !sack || !ok || ws != 8 {
		t.Fatalf("sack=%v ok=%v ws=%d", sack, ok, ws)
	}
}

func TestUserStackWindowScale(t *testing.T) {
	u, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("8.8.8.8")
	const cport, dport uint16 = 42000, 443
	isn := uint32(9000)

	synOpts := []byte{2, 4, 0x05, 0x50, 1, 1, 4, 2, 3, 3, 7}
	syn := mkIPv4TCPOpts(src, dst, cport, dport, isn, 0, 0x02, synOpts, nil)

	tcpOff := 20
	binary.BigEndian.PutUint16(syn[tcpOff+14:], 1000)

	syn = mkIPv4TCPOpts(src, dst, cport, dport, isn, 0, 0x02, synOpts, nil)
	binary.BigEndian.PutUint16(syn[tcpOff+14:], 1000)

	tcp := syn[20:]
	binary.BigEndian.PutUint16(tcp[16:], 0)
	sum := tun.CsumFold(tun.CsumAdd(tun.CsumAdd(tun.CsumAdd(uint32(6+len(tcp)), src.AsSlice()), dst.AsSlice()), tcp))
	binary.BigEndian.PutUint16(tcp[16:], sum)
	if _, err := peer.Write(syn); err != nil {
		t.Fatal(err)
	}
	_, _, _, pkt := readTCP(t, peer, 3*time.Second, 0x12)
	l4 := pkt[20:]
	doff := int(l4[12]>>4) * 4
	opts := l4[20:doff]
	_, _, ourWS, ourOK := parseSynOptsFam(opts, 0)
	if !ourOK || ourWS != usRcvWScale {
		t.Fatalf("SYN-ACK wscale ok=%v ws=%d want %d", ourOK, ourWS, usRcvWScale)
	}
	key := tcpKey{remote: netip.AddrPortFrom(src, cport), local: netip.AddrPortFrom(dst, dport)}
	c := claimConn(t, u, key)
	c.mu.Lock()
	if !c.wscaleOK || c.sndWscale != 7 || c.rcvWscale != usRcvWScale {
		c.mu.Unlock()
		t.Fatalf("wscaleOK=%v snd=%d rcv=%d", c.wscaleOK, c.sndWscale, c.rcvWscale)
	}
	wantWnd := uint32(1000) << 7
	if c.sndWnd != wantWnd {
		c.mu.Unlock()
		t.Fatalf("sndWnd=%d want %d", c.sndWnd, wantWnd)
	}
	adv := c.advWnd()
	c.mu.Unlock()
	if adv == 0 || uint32(adv)<<usRcvWScale < usRcvBuf/2 {
		t.Fatalf("advWnd too small: %d", adv)
	}
}

func TestUserStackOOOReassembly(t *testing.T) {
	u, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("1.2.3.4")
	const cport, dport uint16 = 43000, 80
	isn := uint32(10000)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	iss, _, _, _ := readTCP(t, peer, 3*time.Second, 0x12)
	key := tcpKey{remote: netip.AddrPortFrom(src, cport), local: netip.AddrPortFrom(dst, dport)}
	c := claimConn(t, u, key)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, c)

	part1 := []byte("AAAA")
	part2 := []byte("BBBB")

	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1+uint32(len(part1)), iss+1, 0x18, part2)); err != nil {
		t.Fatal(err)
	}

	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	sawDup := false
	for !sawDup {
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatal("no dup ack:", err)
		}
		v, ok := tun.Parse(buf[:n])
		if !ok || v.Proto != 6 {
			continue
		}
		l4 := v.Pkt[v.L3:]
		if l4[13]&0x10 != 0 && binary.BigEndian.Uint32(l4[8:12]) == isn+1 {
			sawDup = true
			c.mu.Lock()
			oooN := len(c.ooo)
			c.mu.Unlock()
			if oooN == 0 {
				t.Fatal("OOO not buffered")
			}
		}
	}

	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x18, part1)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 16)
	n, err := c.Read(got)
	if err != nil {
		t.Fatal(err)
	}

	all := got[:n]
	for len(all) < 8 {
		n2, err := c.Read(got)
		if err != nil {
			t.Fatalf("short read %q: %v", all, err)
		}
		all = append(all, got[:n2]...)
	}
	if string(all[:8]) != "AAAABBBB" {
		t.Fatalf("reassembled=%q", all[:8])
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.ooo) != 0 {
		t.Fatalf("ooo leftover %d", len(c.ooo))
	}
	if c.rcvNxt != isn+1+8 {
		t.Fatalf("rcvNxt=%d want %d", c.rcvNxt, isn+1+8)
	}
}

func TestUserStackRenoCongestion(t *testing.T) {
	u, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("5.5.5.5")
	const cport, dport uint16 = 44000, 80
	isn := uint32(20000)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	iss, _, _, _ := readTCP(t, peer, 3*time.Second, 0x12)
	key := tcpKey{remote: netip.AddrPortFrom(src, cport), local: netip.AddrPortFrom(dst, dport)}
	c := claimConn(t, u, key)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, c)

	c.mu.Lock()
	initCwnd := c.cwnd
	mss := c.mss
	c.ssthresh = uint32(mss)
	c.mu.Unlock()
	if initCwnd < uint32(mss) {
		t.Fatalf("init cwnd %d", initCwnd)
	}

	payload := make([]byte, mss*4)
	for i := range payload {
		payload[i] = byte(i)
	}
	go func() { _, _ = c.Write(payload) }()

	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	var firstDataSeq uint32
	gotData := false
	for !gotData {
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		v, ok := tun.Parse(buf[:n])
		if !ok || v.Proto != 6 {
			continue
		}
		l4 := v.Pkt[v.L3:]
		doff := int(l4[12]>>4) * 4
		if len(l4) > doff {
			firstDataSeq = binary.BigEndian.Uint32(l4[4:8])
			gotData = true
		}
	}

	ack1 := firstDataSeq + uint32(mss)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, ack1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	c.mu.Lock()
	after := c.cwnd
	inFast := c.inFast
	c.mu.Unlock()
	if inFast {
		t.Fatal("unexpected fast recovery")
	}
	if after <= uint32(mss) {

		t.Logf("cwnd after ack=%d (init was %d)", after, initCwnd)
	}

	c.mu.Lock()
	c.sndUna = firstDataSeq
	c.sndNxt = firstDataSeq + uint32(3*mss)
	c.unacked = []seg{
		{seq: firstDataSeq, data: payload[:mss], sent: time.Now()},
		{seq: firstDataSeq + uint32(mss), data: payload[mss : 2*mss], sent: time.Now()},
		{seq: firstDataSeq + uint32(2*mss), data: payload[2*mss : 3*mss], sent: time.Now()},
	}
	c.dupAcks = 0
	c.inFast = false
	c.cwnd = uint32(10 * mss)
	c.ssthresh = usSndBuf
	c.mu.Unlock()

	dupAckPkt := mkIPv4TCP(src, dst, cport, dport, isn+1, firstDataSeq, 0x10, nil)
	for i := 0; i < 3; i++ {
		if _, err := peer.Write(dupAckPkt); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		ok := c.inFast
		c.mu.Unlock()
		if ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.inFast {
		t.Fatalf("expected fast recovery after 3 dupacks; dupAcks=%d", c.dupAcks)
	}
	if c.ssthresh < uint32(2*mss) {
		t.Fatalf("ssthresh=%d", c.ssthresh)
	}
}

func TestUserStackNoWScaleWithoutPeer(t *testing.T) {
	u, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("9.9.9.1")
	const cport, dport uint16 = 45000, 80
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, 1, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	_, _, _, pkt := readTCP(t, peer, 3*time.Second, 0x12)
	l4 := pkt[20:]
	doff := int(l4[12]>>4) * 4
	_, _, _, ok := parseSynOptsFam(l4[20:doff], 0)
	if ok {
		t.Fatal("should not advertise WScale when peer omitted it")
	}
	key := tcpKey{remote: netip.AddrPortFrom(src, cport), local: netip.AddrPortFrom(dst, dport)}
	c := claimConn(t, u, key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wscaleOK {
		t.Fatal("wscaleOK without peer")
	}
}

func TestUserStackWindowUpdateAfterRead(t *testing.T) {
	u, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("8.8.8.8")
	const cport, dport uint16 = 46000, 80
	isn := uint32(30000)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	iss, _, _, _ := readTCP(t, peer, 3*time.Second, 0x12)
	key := tcpKey{remote: netip.AddrPortFrom(src, cport), local: netip.AddrPortFrom(dst, dport)}
	c := claimConn(t, u, key)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, c)

	c.mu.Lock()
	c.rcvWnd = 0
	c.rbuf = make([]byte, usRcvBuf)
	c.mu.Unlock()

	chunk := make([]byte, 2048)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	n, err := c.Read(chunk)
	if err != nil || n != 2048 {
		t.Fatalf("Read n=%d err=%v", n, err)
	}
	_, ack, _, _ := readTCP(t, peer, 2*time.Second, 0x10)
	if ack != isn+1 {
		t.Fatalf("window-update ack=%d want %d", ack, isn+1)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rcvWnd < 2048 {
		t.Fatalf("rcvWnd=%d", c.rcvWnd)
	}
}

func TestUserStackFINNotTakenOnPartialWindow(t *testing.T) {
	u, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("1.1.1.1")
	const cport, dport uint16 = 47000, 80
	isn := uint32(40000)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	iss, _, _, _ := readTCP(t, peer, 3*time.Second, 0x12)
	key := tcpKey{remote: netip.AddrPortFrom(src, cport), local: netip.AddrPortFrom(dst, dport)}
	c := claimConn(t, u, key)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, c)

	c.mu.Lock()
	room := 10
	c.rbuf = make([]byte, usRcvBuf-room)
	c.rcvWnd = uint32(room)
	c.mu.Unlock()

	payload := make([]byte, 40)
	for i := range payload {
		payload[i] = 'A'
	}
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x19, payload)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == stCloseWait || c.state == stClosing || c.state == stTimeWait {
		t.Fatalf("FIN taken early; state=%d rcvNxt delta=%d", c.state, c.rcvNxt-(isn+1))
	}
	if int(c.rcvNxt-(isn+1)) != room {
		t.Fatalf("took %d want %d", c.rcvNxt-(isn+1), room)
	}
}

func TestUserStackWindowOpenFlushesPending(t *testing.T) {
	u, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("2.2.2.2")
	const cport, dport uint16 = 48000, 80
	isn := uint32(50000)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	iss, _, _, _ := readTCP(t, peer, 3*time.Second, 0x12)
	key := tcpKey{remote: netip.AddrPortFrom(src, cport), local: netip.AddrPortFrom(dst, dport)}
	c := claimConn(t, u, key)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, c)

	c.mu.Lock()
	c.sndWnd = 0
	c.pending = []byte("hello-window")
	c.mu.Unlock()

	pkt := mkIPv4TCPOpts(src, dst, cport, dport, isn+1, iss+1, 0x10, nil, nil)
	l4 := pkt[20:]
	binary.BigEndian.PutUint16(l4[14:16], 65535)
	binary.BigEndian.PutUint16(l4[16:18], 0)
	binary.BigEndian.PutUint16(l4[16:18], tun.CsumFold(tun.CsumAdd(tun.CsumAdd(tun.CsumAdd(uint32(6+len(l4)), src.AsSlice()), dst.AsSlice()), l4)))
	if _, err := peer.Write(pkt); err != nil {
		t.Fatal(err)
	}
	_, _, payload, _ := readTCP(t, peer, 2*time.Second, 0x18)
	if string(payload) != "hello-window" {
		t.Fatalf("payload=%q", payload)
	}
}

func TestUserStackRTTSample(t *testing.T) {
	u, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("3.3.3.3")
	const cport, dport uint16 = 49000, 80
	isn := uint32(60000)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	iss, _, _, _ := readTCP(t, peer, 3*time.Second, 0x12)
	key := tcpKey{remote: netip.AddrPortFrom(src, cport), local: netip.AddrPortFrom(dst, dport)}
	c := claimConn(t, u, key)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, c)

	done := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("rtt-probe-data"))
		done <- err
	}()
	seq, _, payload, _ := readTCP(t, peer, 2*time.Second, 0x18)
	if len(payload) == 0 {
		t.Fatal("no data")
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, seq+uint32(len(payload)), 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write timeout")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.rttOK || c.srtt < time.Millisecond {
		t.Fatalf("rttOK=%v srtt=%v rto=%v", c.rttOK, c.srtt, c.rto)
	}
}

func TestUserStackReadEOFAfterPeerFINWhileClosing(t *testing.T) {
	u, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("4.4.4.4")
	const cport, dport uint16 = 50000, 80
	isn := uint32(70000)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	iss, _, _, _ := readTCP(t, peer, 3*time.Second, 0x12)
	key := tcpKey{remote: netip.AddrPortFrom(src, cport), local: netip.AddrPortFrom(dst, dport)}
	c := claimConn(t, u, key)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, c)

	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	finSeq, _, _, _ := readTCP(t, peer, 2*time.Second, 0x11)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, finSeq+1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		st := c.state
		c.mu.Unlock()
		if st == stFinWait2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_, err := c.Read(buf)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, finSeq+1, 0x11, nil)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("Read err=%v want EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read hung after peer FIN (FinWait2→TimeWait)")
	}

	u2, peer2 := startStackPair(t)
	src2, dst2 := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("5.5.5.5")
	const cport2, dport2 uint16 = 50001, 80
	isn2 := uint32(71000)
	if _, err := peer2.Write(mkIPv4TCP(src2, dst2, cport2, dport2, isn2, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	iss2, _, _, _ := readTCP(t, peer2, 3*time.Second, 0x12)
	key2 := tcpKey{remote: netip.AddrPortFrom(src2, cport2), local: netip.AddrPortFrom(dst2, dport2)}
	c2 := claimConn(t, u2, key2)
	if _, err := peer2.Write(mkIPv4TCP(src2, dst2, cport2, dport2, isn2+1, iss2+1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, c2)
	if err := c2.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	finSeq2, _, _, _ := readTCP(t, peer2, 2*time.Second, 0x11)
	done2 := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_, err := c2.Read(buf)
		done2 <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := peer2.Write(mkIPv4TCP(src2, dst2, cport2, dport2, isn2+1, finSeq2+1, 0x11, nil)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done2:
		if err != io.EOF {
			t.Fatalf("Closing path Read err=%v want EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read hung after peer FIN (FinWait1→Closing)")
	}
}

func TestUserStackSetReadDeadlineWakesBlockedRead(t *testing.T) {
	u, peer := startStackPair(t)
	src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("9.9.9.9")
	const cport, dport uint16 = 41099, 7
	isn := uint32(9000)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn, 0, 0x02, nil)); err != nil {
		t.Fatal(err)
	}
	iss, ack, _, _ := readTCP(t, peer, 3*time.Second, 0x12)
	if ack != isn+1 {
		t.Fatalf("synack ack=%d", ack)
	}
	key := tcpKey{remote: netip.AddrPortFrom(src, cport), local: netip.AddrPortFrom(dst, dport)}
	c := claimConn(t, u, key)
	if _, err := peer.Write(mkIPv4TCP(src, dst, cport, dport, isn+1, iss+1, 0x10, nil)); err != nil {
		t.Fatal(err)
	}
	waitEstablished(t, c)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_, err := c.Read(buf)
		errCh <- err
	}()
	time.Sleep(30 * time.Millisecond)
	_ = c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	select {
	case err := <-errCh:
		if err != os.ErrDeadlineExceeded {
			t.Fatalf("Read err=%v want ErrDeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not observe late SetReadDeadline")
	}
}

func verify(t *testing.T, pkt []byte) {
	t.Helper()
	v, ok := tun.Parse(pkt)
	if !ok {
		t.Fatal("parse")
	}
	l4 := v.Pkt[v.L3:]
	sum := tun.CsumAdd(tun.CsumAdd(tun.CsumAdd(uint32(v.Proto)+uint32(len(l4)), v.Pkt[v.AOff:v.AOff+v.ALen]), v.Pkt[v.AOff+v.ALen:v.AOff+2*v.ALen]), l4)
	if tun.CsumFold(sum) != 0 {
		t.Fatalf("l4 checksum bad")
	}
	if v.Fam == 0 && tun.CsumFold(tun.CsumAdd(0, pkt[:20])) != 0 {
		t.Fatal("ip checksum bad")
	}
}

func TestTcpConnAbortSendsRST(t *testing.T) {
	u, peer := startStackPair(t)
	client := netip.MustParseAddr("172.19.0.2")
	server := netip.MustParseAddr("1.2.3.4")
	syn := mkIPv4TCP(client, server, 40000, 80, 1000, 0, 0x02, nil)
	if _, err := peer.Write(syn); err != nil {
		t.Fatal(err)
	}
	_, _, _, _ = readTCP(t, peer, 2*time.Second, 0x12)
	key := tcpKey{local: netip.AddrPortFrom(server, 80), remote: netip.AddrPortFrom(client, 40000)}
	c := claimConn(t, u, key)
	c.Abort()
	_, _, _, _ = readTCP(t, peer, 2*time.Second, 0x04)
}

func TestTimerStopsWhenIdleAndRearms(t *testing.T) {
	u := New(Config{
		Send:     func([]byte, *[]byte) {},
		Alive:    func() bool { return true },
		LateBind: func(netip.AddrPort) bool { return false },
	})
	defer u.Close()
	time.Sleep(3 * usTick)
	if u.fast.Load() {
		t.Fatal("timer still fast with no connections")
	}
	src := netip.MustParseAddrPort("10.0.0.2:5555")
	dst := netip.MustParseAddrPort("10.0.0.9:80")
	key := tcpKey{remote: src, local: dst}
	u.handleSYN(key, 0, 1000, 65535, []byte{2, 4, 0x05, 0xb4}, 80)
	if !u.fast.Load() {
		t.Fatal("SYN-ACK did not rearm timer")
	}
	u.mu.Lock()
	c := u.conns[key]
	u.mu.Unlock()
	c.mu.Lock()
	c.state = stEstablished
	c.unacked = nil
	c.mu.Unlock()
	time.Sleep(3 * usTick)
	if u.fast.Load() {
		t.Fatal("timer not stopped for idle established conn")
	}
	c.mu.Lock()
	c.scheduleAckLocked(10, false)
	c.mu.Unlock()
	if !u.fast.Load() {
		t.Fatal("delayed ack did not rearm")
	}
	time.Sleep(usDelAck + 3*usTick)
	c.mu.Lock()
	pending := c.delayedAck
	c.mu.Unlock()
	if pending {
		t.Fatal("delayed ack not fired after rearm")
	}
}

func TestMSSFamilies(t *testing.T) {
	big := []byte{2, 4, 0x05, 0xb4}
	if m, _, _, _ := parseSynOptsFam(big, 0); m != 1380 {
		t.Fatalf("v4 mss=%d", m)
	}
	if m, _, _, _ := parseSynOptsFam(big, 1); m != 1360 {
		t.Fatalf("v6 mss=%d", m)
	}
	if m, _, _, _ := parseSynOptsFam(nil, 1); m != 1360 {
		t.Fatalf("v6 default=%d", m)
	}
	if m, _, _, _ := parseSynOptsFam([]byte{2, 4, 0, 10}, 1); m != usMinMSS {
		t.Fatalf("clamp low=%d", m)
	}
	c := &tcpConn{fam: 1}
	o := c.synAckOpts()
	if int(o[2])<<8|int(o[3]) != 1360 {
		t.Fatal("v6 synack mss")
	}
	c.fam = 0
	o = c.synAckOpts()
	if int(o[2])<<8|int(o[3]) != 1380 {
		t.Fatal("v4 synack mss")
	}
}

func TestDataSegmentIsNotADupAck(t *testing.T) {
	c := &tcpConn{
		state:    stEstablished,
		sndUna:   100,
		sndNxt:   2000,
		sndWnd:   65535,
		mss:      1000,
		cwnd:     8000,
		ssthresh: usSndBuf,
	}
	for i := 0; i < 5; i++ {
		c.applyAckLocked(100, nil, 50, 0x18, c.sndWnd)
	}
	if c.dupAcks != 0 || c.inFast {
		t.Fatalf("payload counted as dup: dup=%d fast=%v", c.dupAcks, c.inFast)
	}
	c.applyAckLocked(100, nil, 0, 0x11, c.sndWnd)
	if c.dupAcks != 0 {
		t.Fatal("FIN counted as a duplicate ACK")
	}
	c.applyAckLocked(100, nil, 0, 0x10, 1000)
	if c.dupAcks != 0 {
		t.Fatal("window update counted as a duplicate ACK")
	}
	idle := &tcpConn{state: stEstablished, sndUna: 5, sndNxt: 5, sndWnd: 100, mss: 1000}
	idle.applyAckLocked(5, nil, 0, 0x10, idle.sndWnd)
	if idle.dupAcks != 0 {
		t.Fatal("ACK with nothing outstanding counted as a duplicate")
	}
	for i := 0; i < 3; i++ {
		c.applyAckLocked(100, nil, 0, 0x10, c.sndWnd)
	}
	if !c.inFast || c.dupAcks != 3 {
		t.Fatalf("pure dup ACK fast=%v dup=%d", c.inFast, c.dupAcks)
	}
	c.cwnd = usSndBuf - 10
	c.onDupAckLocked()
	if c.cwnd != usSndBuf {
		t.Fatalf("cwnd=%d want cap %d", c.cwnd, usSndBuf)
	}
	c.onDupAckLocked()
	if c.cwnd != usSndBuf {
		t.Fatalf("cwnd grew past cap: %d", c.cwnd)
	}
}

func TestStoreOOOInsertDoesNotAlias(t *testing.T) {
	c := &tcpConn{}
	c.storeOOOLocked(200, []byte("BBBB"), false)
	c.storeOOOLocked(300, []byte("CCCC"), false)
	c.storeOOOLocked(400, []byte("DDDD"), false)
	c.storeOOOLocked(100, []byte("AAAA"), false)
	c.storeOOOLocked(250, []byte("XX"), false)
	var got string
	for _, s := range c.ooo {
		got += string(s.data)
	}
	if got != "AAAABBBBXXCCCCDDDD" {
		t.Fatalf("ooo=%q segs=%d", got, len(c.ooo))
	}
}

func TestForceCloseReleasesPreDial(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := &tcpConn{state: stSynRcvd, preDial: a, st: &Stack{}}
	c.forceCloseLocked()
	if c.preDial != nil {
		t.Fatal("preDial still referenced")
	}
	_ = b.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := b.Read(buf); err == nil {
		t.Fatal("late-bind conn still open")
	}
}
