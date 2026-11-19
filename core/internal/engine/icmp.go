package engine

import (
	"arc/core/internal/dns"
	"arc/core/internal/engine/tun"
	"arc/core/internal/protect"
	"arc/core/internal/router"
	"encoding/binary"
	"net/netip"
	"os"
	"syscall"
	"time"
)

func (s *CustomStack) handleICMP(tf *os.File, v tun.View) {
	icmp := v.Pkt[v.L3:]
	if len(icmp) < 8 {
		return
	}
	req := byte(8)
	if v.Fam == 1 {
		req = 128
	}
	if icmp[0] != req || icmp[1] != 0 {
		return
	}
	src, dst := v.Addr(0), v.Addr(1)
	act := router.MatchIP(dst)
	if _, fake, _ := dns.LookupDest(dst); fake {
		act = router.ActionProxy
	}
	id, seq := binary.BigEndian.Uint16(icmp[4:6]), binary.BigEndian.Uint16(icmp[6:8])
	data := append([]byte(nil), icmp[8:]...)
	if router.IsDirectOrLAN(act) || router.IsDirectIP(dst) {
		go func() {
			if reply, ok := realPing(dst, id, seq, data); ok {
				s.injectEcho(tf, dst, src, id, seq, reply)
			}
		}()
		return
	}
	s.injectEcho(tf, dst, src, id, seq, data)
}

func realPing(dst netip.Addr, id, seq uint16, data []byte) ([]byte, bool) {
	fam, proto, typ := syscall.AF_INET, syscall.IPPROTO_ICMP, byte(8)
	if dst.Is6() {
		fam, proto, typ = syscall.AF_INET6, syscall.IPPROTO_ICMPV6, 128
	}
	fd, err := syscall.Socket(fam, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, false
	}
	defer syscall.Close(fd)
	if !protect.ProtectFD(fd) {
		return nil, false
	}
	tv := syscall.Timeval{Sec: 3}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	msg := make([]byte, 8+len(data))
	msg[0] = typ
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[8:], data)
	var sa syscall.Sockaddr
	if dst.Is4() {
		sa = &syscall.SockaddrInet4{Addr: dst.As4()}
	} else {
		sa = &syscall.SockaddrInet6{Addr: dst.As16()}
	}
	if err := syscall.Sendto(fd, msg, 0, sa); err != nil {
		return nil, false
	}
	buf := make([]byte, 65535)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, false
		}
		if n >= 8 && binary.BigEndian.Uint16(buf[6:8]) == seq && (buf[0] == 0 || buf[0] == 129) {
			return append([]byte(nil), buf[8:n]...), true
		}
	}
	return nil, false
}

// sendICMP wraps an ICMP / ICMPv6 message (type, code, 4-byte rest of
// header, body) in an IP header from -> to and queues it on the TUN.
func (s *CustomStack) sendICMP(tf *os.File, from, to netip.Addr, typ, code byte, rest uint32, body []byte) {
	hl := 40
	if from.Is4() {
		hl = 20
	}
	pkt := make([]byte, hl+8+len(body))
	ic := pkt[hl:]
	ic[0], ic[1] = typ, code
	binary.BigEndian.PutUint32(ic[4:8], rest)
	copy(ic[8:], body)
	if hl == 20 {
		pkt[0], pkt[8], pkt[9] = 0x45, 64, 1
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		tun.PutAddr(pkt[12:16], from)
		tun.PutAddr(pkt[16:20], to)
		binary.BigEndian.PutUint16(pkt[10:12], tun.CsumFold(tun.CsumAdd(0, pkt[:20])))
		binary.BigEndian.PutUint16(ic[2:4], tun.CsumFold(tun.CsumAdd(0, ic)))
	} else {
		pkt[0], pkt[6], pkt[7] = 0x60, 58, 64
		binary.BigEndian.PutUint16(pkt[4:6], uint16(len(ic)))
		tun.PutAddr(pkt[8:24], from)
		tun.PutAddr(pkt[24:40], to)
		sum := tun.CsumAdd(tun.CsumAdd(tun.CsumAdd(uint32(58+len(ic)), pkt[8:24]), pkt[24:40]), ic)
		binary.BigEndian.PutUint16(ic[2:4], tun.CsumFold(sum))
	}
	s.send(tf, pkt, nil)
}

func (s *CustomStack) injectEcho(tf *os.File, from, to netip.Addr, id, seq uint16, data []byte) {
	typ := byte(0)
	if from.Is6() {
		typ = 129
	}
	s.sendICMP(tf, from, to, typ, 0, uint32(id)<<16|uint32(seq), data)
}

// portUnreachable quotes the offending packet within the RFC 1812 / 4443
// minimum-MTU budgets (576 and 1280 bytes).
func (s *CustomStack) portUnreachable(tf *os.File, v tun.View) {
	if v.Fam == 0 {
		s.sendICMP(tf, v.Addr(1), v.Addr(0), 3, 3, 0, v.Pkt[:min(len(v.Pkt), 548)])
	} else {
		s.sendICMP(tf, v.Addr(1), v.Addr(0), 1, 4, 0, v.Pkt[:min(len(v.Pkt), 1232)])
	}
}
