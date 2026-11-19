package dnswire

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

const (
	TypeA    uint16 = 1
	TypeAAAA uint16 = 28
)

func Query(domain string, qtype uint16) []byte {
	buf := append(make([]byte, 0, 64), 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			if i > start {
				buf = append(append(buf, byte(i-start)), domain[start:i]...)
			}
			start = i + 1
		}
	}
	return append(buf, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
}

func skipName(w []byte, off int) int {
	for off < len(w) {
		l := int(w[off])
		if l == 0 {
			return off + 1
		}
		if l&0xC0 == 0xC0 {
			return off + 2
		}
		if l&0xC0 != 0 {
			// Reserved label types 01/10 (RFC 1035 4.1.4): stop the walk.
			return len(w) + 1
		}
		off += 1 + l
	}
	return off
}

func Question(pkt []byte) (domain string, qtype uint16, qEnd int, ok bool) {
	if len(pkt) < 17 || binary.BigEndian.Uint16(pkt[4:6]) == 0 {
		return "", 0, 0, false
	}
	var buf [256]byte
	n, off := 0, 12
	for off < len(pkt) {
		l := int(pkt[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 != 0 || off+1+l > len(pkt) || n+l+1 > len(buf) {
			return "", 0, 0, false
		}
		if n > 0 {
			buf[n] = '.'
			n++
		}
		for _, c := range pkt[off+1 : off+1+l] {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			buf[n] = c
			n++
		}
		off += 1 + l
	}
	if off+4 > len(pkt) || n == 0 {
		return "", 0, 0, false
	}
	return string(buf[:n]), binary.BigEndian.Uint16(pkt[off : off+2]), off + 4, true
}

func Answer(req []byte, qEnd int, rcode byte, qtype uint16, ttl uint32, rdata []byte) []byte {
	out := make([]byte, qEnd, qEnd+12+len(rdata))
	copy(out, req[:qEnd])
	out[2], out[3] = 0x81, 0x80|rcode
	out[4], out[5] = 0, 1
	clear(out[6:12])
	if rdata != nil {
		out[7] = 1
		out = binary.BigEndian.AppendUint16(append(out, 0xC0, 0x0C), qtype)
		out = binary.BigEndian.AppendUint32(append(out, 0, 1), ttl)
		out = append(binary.BigEndian.AppendUint16(out, uint16(len(rdata))), rdata...)
	}
	return out
}

func eachRR(w []byte, f func(rtype uint16, rdata []byte) bool) (minTTL uint32, ok bool) {
	if len(w) < 12 {
		return 0, false
	}
	an := int(binary.BigEndian.Uint16(w[6:8]))
	off := 12
	for range binary.BigEndian.Uint16(w[4:6]) {
		off = skipName(w, off) + 4
	}
	minTTL = ^uint32(0)
	for i := 0; i < an; i++ {
		off = skipName(w, off)
		if off+10 > len(w) {
			return minTTL, false
		}
		rtype, ttl := binary.BigEndian.Uint16(w[off:]), binary.BigEndian.Uint32(w[off+4:])
		rdlen := int(binary.BigEndian.Uint16(w[off+8:]))
		off += 10
		if off+rdlen > len(w) {
			return minTTL, false
		}
		minTTL = min(minTTL, ttl)
		if f != nil && f(rtype, w[off:off+rdlen]) {
			return minTTL, true
		}
		off += rdlen
	}
	return minTTL, true
}

func FirstIP(w []byte) (ip netip.Addr, err error) {
	eachRR(w, func(t uint16, d []byte) bool {
		if t == TypeA && len(d) == 4 {
			ip = netip.AddrFrom4([4]byte(d))
		} else if t == TypeAAAA && len(d) == 16 {
			ip = netip.AddrFrom16([16]byte(d))
		}
		return ip.IsValid()
	})
	if !ip.IsValid() {
		return ip, errors.New("no ip")
	}
	return ip, nil
}

func MinTTL(w []byte) uint32 {
	t, ok := eachRR(w, nil)
	if !ok || t == ^uint32(0) {
		return 0
	}
	return t
}

func Race[T any](ctx context.Context, timeout time.Duration, n int, f func(ctx context.Context, i int) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type res struct {
		v   T
		err error
	}
	ch := make(chan res, n)
	for i := range n {
		go func() {
			v, err := f(ctx, i)
			ch <- res{v, err}
		}()
	}
	var zero T
	var err error
	for left := n; left > 0; left-- {
		select {
		case r := <-ch:
			if r.err == nil {
				return r.v, nil
			}
			err = r.err
		case <-ctx.Done():
			select {
			case r := <-ch:
				if r.err == nil {
					return r.v, nil
				}
				if err == nil {
					err = r.err
				}
			default:
			}
			if err == nil {
				err = ctx.Err()
			}
			return zero, err
		}
	}
	if err == nil {
		err = errors.New("race: no candidates")
	}
	return zero, err
}

func EachIP(w []byte, f func(netip.Addr) bool) {
	eachRR(w, func(t uint16, d []byte) bool {
		if t == TypeA && len(d) == 4 {
			return f(netip.AddrFrom4([4]byte(d)))
		} else if t == TypeAAAA && len(d) == 16 {
			return f(netip.AddrFrom16([16]byte(d)))
		}
		return false
	})
}

func Rcode(w []byte) int {
	if len(w) < 12 {
		return -1
	}
	return int(w[3] & 0x0F)
}

func AnswerCount(w []byte) int {
	if len(w) < 12 {
		return 0
	}
	return int(binary.BigEndian.Uint16(w[6:8]))
}

func NegativeTTL(w []byte) (ttl uint32, ok bool) {
	if len(w) < 12 {
		return 0, false
	}
	off := 12
	for range binary.BigEndian.Uint16(w[4:6]) {
		off = skipName(w, off) + 4
	}
	an, ns := int(binary.BigEndian.Uint16(w[6:8])), int(binary.BigEndian.Uint16(w[8:10]))
	for i := 0; i < an+ns; i++ {
		off = skipName(w, off)
		if off+10 > len(w) {
			return 0, false
		}
		rtype, rttl := binary.BigEndian.Uint16(w[off:]), binary.BigEndian.Uint32(w[off+4:])
		rdlen := int(binary.BigEndian.Uint16(w[off+8:]))
		off += 10
		if off+rdlen > len(w) {
			return 0, false
		}
		if i >= an && rtype == 6 {
			end := off + rdlen
			p := skipName(w, skipName(w, off))
			if p+20 != end {
				return 0, false
			}
			return min(rttl, binary.BigEndian.Uint32(w[p+16:])), true
		}
		off += rdlen
	}
	return 0, false
}

func WithTTL(w []byte, ttl uint32) []byte {
	out := append([]byte(nil), w...)
	if len(out) < 12 {
		return out
	}
	off := 12
	for range binary.BigEndian.Uint16(out[4:6]) {
		off = skipName(out, off) + 4
	}
	n := int(binary.BigEndian.Uint16(out[6:8])) + int(binary.BigEndian.Uint16(out[8:10]))
	for i := 0; i < n; i++ {
		off = skipName(out, off)
		if off+10 > len(out) {
			return out
		}
		rdlen := int(binary.BigEndian.Uint16(out[off+8:]))
		if off+10+rdlen > len(out) {
			// Truncated record: leave it and the rest untouched.
			return out
		}
		binary.BigEndian.PutUint32(out[off+4:], ttl)
		off += 10 + rdlen
	}
	return out
}
