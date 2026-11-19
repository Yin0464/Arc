package tun

import (
	"encoding/binary"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// MTU is the TUN interface MTU (ArcVpnService setMtu 1420). A full
	// ustack segment is exactly 1420 bytes, so it must not be fragmented.
	MTU          = 1420
	fragTimeout  = 30 * time.Second
	maxFragFlows = 64
)

type fragKey struct {
	src, dst netip.Addr
	id       uint32
	proto    byte
}

type fragFlow struct {
	hdr     []byte
	data    []byte
	filled  []byte
	got     int
	total   int
	started time.Time
}

type reassembler struct {
	mu    sync.Mutex
	flows map[fragKey]*fragFlow
}

var frags = reassembler{flows: map[fragKey]*fragFlow{}}

func (r *reassembler) add(k fragKey, off int, more bool, payload, hdr4 []byte) ([]byte, []byte) {
	if off+len(payload) > 65535 || (more && len(payload)%8 != 0) {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.flows[k]
	if f == nil {
		now := time.Now()
		if len(r.flows) >= maxFragFlows {
			for kk, ff := range r.flows {
				if now.Sub(ff.started) > fragTimeout || len(r.flows) >= maxFragFlows {
					delete(r.flows, kk)
				}
			}
		}
		f = &fragFlow{total: -1, started: now}
		r.flows[k] = f
	}
	end := off + len(payload)
	if f.total >= 0 && end > f.total {
		// Past the end the final fragment already fixed: malformed, drop it.
		return nil, nil
	}
	if !more && len(f.data) > end {
		// The final fragment ends before data already received: the
		// datagram is inconsistent, discard all of it.
		delete(r.flows, k)
		return nil, nil
	}
	if need := end; need > len(f.data) {
		n := need - len(f.data)
		f.data = append(f.data, make([]byte, n)...)
		f.filled = append(f.filled, make([]byte, n)...)
	}
	for i, b := range payload {
		pos := off + i
		if f.filled[pos] == 0 {
			f.filled[pos] = 1
			f.got++
		}
		f.data[pos] = b
	}
	if off == 0 && hdr4 != nil {
		f.hdr = append([]byte(nil), hdr4...)
	}
	if !more {
		f.total = end
	}
	if f.total < 0 || f.got < f.total || (hdr4 != nil && f.hdr == nil) {
		if f.got > 65535 {
			delete(r.flows, k)
		}
		return nil, nil
	}
	delete(r.flows, k)
	return f.data[:f.total], f.hdr
}

func reassemble(pkt []byte) []byte {
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0F) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		if ihl < 20 || total > len(pkt) || total <= ihl {
			return nil
		}
		fo := binary.BigEndian.Uint16(pkt[6:8])
		src, _ := netip.AddrFromSlice(pkt[12:16])
		dst, _ := netip.AddrFromSlice(pkt[16:20])
		k := fragKey{src, dst, uint32(binary.BigEndian.Uint16(pkt[4:6])), pkt[9]}
		var h []byte
		if fo&0x1fff == 0 {
			h = pkt[:ihl]
		}
		data, hdr := frags.add(k, int(fo&0x1fff)*8, fo&0x2000 != 0, pkt[ihl:total], h)
		if data == nil || len(hdr)+len(data) > 65535 {
			// add already dropped the flow; a datagram whose header plus
			// payload overflows the IPv4 total length is discarded.
			return nil
		}
		out := make([]byte, len(hdr)+len(data))
		copy(out, hdr)
		copy(out[len(hdr):], data)
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		binary.BigEndian.PutUint16(out[6:8], 0)
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:12], CsumFold(CsumAdd(0, out[:len(hdr)])))
		return out
	case 6:
		return nil
	}
	return nil
}

func ipv6Payload(pkt []byte) (proto byte, off int, rebuilt []byte, isFrag bool) {
	nh, off := pkt[6], 40
	for {
		switch nh {
		case 0, 43, 60:
			if len(pkt) < off+8 {
				return 0, 0, nil, false
			}
			nh, off = pkt[off], off+(int(pkt[off+1])+1)*8
		case 51:
			if len(pkt) < off+8 {
				return 0, 0, nil, false
			}
			nh, off = pkt[off], off+(int(pkt[off+1])+2)*4
		case 44:
			if len(pkt) < off+8 {
				return 0, 0, nil, false
			}
			next := pkt[off]
			fo := binary.BigEndian.Uint16(pkt[off+2 : off+4])
			id := binary.BigEndian.Uint32(pkt[off+4 : off+8])
			src, _ := netip.AddrFromSlice(pkt[8:24])
			dst, _ := netip.AddrFromSlice(pkt[24:40])
			data, _ := frags.add(fragKey{src, dst, id, next}, int(fo>>3)*8, fo&1 != 0, pkt[off+8:], nil)
			if data == nil {
				return 0, 0, nil, true
			}
			out := make([]byte, 40+len(data))
			copy(out, pkt[:40])
			out[6] = next
			binary.BigEndian.PutUint16(out[4:6], uint16(len(data)))
			copy(out[40:], data)
			return next, 40, out, true
		default:
			if off > len(pkt) {
				return 0, 0, nil, false
			}
			return nh, off, nil, false
		}
	}
}

var fragID atomic.Uint32

func WritePacket(tun *os.File, pkt []byte) error {
	if len(pkt) <= MTU {
		_, err := tun.Write(pkt)
		return err
	}
	id := fragID.Add(1)
	// tun.Write copies synchronously, so the pooled buffer is free on return.
	bp := BufPool.Get().(*[]byte)
	defer BufPool.Put(bp)
	buf := (*bp)[:MTU]
	if pkt[0]>>4 == 4 {
		hl := int(pkt[0]&0x0F) * 4
		body := pkt[hl:]
		step := (MTU - hl) &^ 7
		for o := 0; o < len(body); o += step {
			n := min(step, len(body)-o)
			f := buf[:hl+n]
			copy(f, pkt[:hl])
			copy(f[hl:], body[o:o+n])
			fo := uint16(o / 8)
			if o+n < len(body) {
				fo |= 0x2000
			}
			binary.BigEndian.PutUint16(f[2:4], uint16(hl+n))
			binary.BigEndian.PutUint16(f[4:6], uint16(id))
			binary.BigEndian.PutUint16(f[6:8], fo)
			f[10], f[11] = 0, 0
			binary.BigEndian.PutUint16(f[10:12], CsumFold(CsumAdd(0, f[:hl])))
			if _, err := tun.Write(f); err != nil {
				return err
			}
		}
		return nil
	}
	body := pkt[40:]
	step := (MTU - 48) &^ 7
	for o := 0; o < len(body); o += step {
		n := min(step, len(body)-o)
		f := buf[:48+n]
		copy(f, pkt[:40])
		f[6] = 44
		binary.BigEndian.PutUint16(f[4:6], uint16(8+n))
		f[40], f[41] = pkt[6], 0
		fo := uint16(o/8) << 3
		if o+n < len(body) {
			fo |= 1
		}
		binary.BigEndian.PutUint16(f[42:44], fo)
		binary.BigEndian.PutUint32(f[44:48], id)
		copy(f[48:], body[o:o+n])
		if _, err := tun.Write(f); err != nil {
			return err
		}
	}
	return nil
}
