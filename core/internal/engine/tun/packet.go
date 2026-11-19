package tun

import (
	"encoding/binary"
	"net/netip"
	"sync"
)

// BufPool holds 2048-byte packet buffers shared by every TUN producer.
var BufPool = sync.Pool{New: func() any { b := make([]byte, 2048); return &b }}

// View is a parsed IP packet: Fam is 0 for IPv4 and 1 for IPv6, L3 is the
// transport header offset, and the source/destination addresses sit at
// AOff with length ALen.
type View struct {
	Pkt                 []byte
	Fam, L3, AOff, ALen int
	Proto               byte
}

func (v View) Addr(i int) netip.Addr {
	a, _ := netip.AddrFromSlice(v.Pkt[v.AOff+i*v.ALen : v.AOff+(i+1)*v.ALen])
	return a
}

func Parse(pkt []byte) (v View, ok bool) {
	if len(pkt) < 20 {
		return v, false
	}
	switch pkt[0] >> 4 {
	case 4:
		ihl, total := int(pkt[0]&0x0F)*4, int(binary.BigEndian.Uint16(pkt[2:4]))
		if ihl < 20 || total < ihl || total > len(pkt) {
			return v, false
		}
		if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
			if pkt = reassemble(pkt[:total]); pkt == nil {
				return v, false
			}
			total = len(pkt)
		}
		if total < ihl+8 {
			return v, false
		}
		return View{pkt[:total], 0, ihl, 12, 4, pkt[9]}, true
	case 6:
		if len(pkt) < 40 {
			return v, false
		}
		total := 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
		if total > len(pkt) {
			return v, false
		}
		pkt = pkt[:total]
		proto, l3, rebuilt, frag := ipv6Payload(pkt)
		if frag {
			if rebuilt == nil {
				return v, false
			}
			pkt = rebuilt
		}
		if l3 == 0 || len(pkt) < l3+8 {
			return v, false
		}
		return View{pkt, 1, l3, 8, 16, proto}, true
	}
	return v, false
}

func PutAddr(dst []byte, a netip.Addr) {
	if a.Is4() {
		b := a.As4()
		copy(dst, b[:])
		return
	}
	b := a.As16()
	copy(dst, b[:])
}

func CsumAdd(sum uint32, b []byte) uint32 {
	var s0, s1, s2, s3 uint32
	s0 = sum
	for len(b) >= 8 {
		s0 += uint32(b[0])<<8 | uint32(b[1])
		s1 += uint32(b[2])<<8 | uint32(b[3])
		s2 += uint32(b[4])<<8 | uint32(b[5])
		s3 += uint32(b[6])<<8 | uint32(b[7])
		b = b[8:]
	}
	sum = s0 + s1 + s2 + s3
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func CsumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}
