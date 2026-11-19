package engine

import (
	"arc/core/internal/engine/tun"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"testing"
)

func udpPacket(t *testing.T, src, dst netip.AddrPort, n int) []byte {
	r, w, _ := os.Pipe()
	defer r.Close()
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i)
	}
	done := make(chan []byte)
	go func() {
		var all [][]byte
		buf := make([]byte, 70000)
		for {
			k, err := r.Read(buf)
			if err != nil {
				break
			}
			all = append(all, append([]byte(nil), buf[:k]...))
		}

		var flat []byte
		for _, a := range all {
			flat = append(flat, a...)
		}
		var out []byte
		for len(flat) > 0 {
			var l int
			if flat[0]>>4 == 4 {
				l = int(binary.BigEndian.Uint16(flat[2:4]))
			} else {
				l = 40 + int(binary.BigEndian.Uint16(flat[4:6]))
			}
			if l > tun.MTU {
				t.Errorf("fragment %d > MTU", l)
			}
			if v, ok := tun.Parse(flat[:l]); ok {
				out = v.Pkt
			}
			flat = flat[l:]
		}
		done <- out
	}()
	writeUDP(&CustomStack{}, w, src, dst, payload)
	w.Close()
	return <-done
}

func TestFragmentRoundTrip(t *testing.T) {
	for _, pair := range [][2]string{{"1.2.3.4:53", "172.19.0.1:5000"}, {"[2400::1]:443", "[fdfe:dcba:9876::1]:5000"}} {
		src, dst := netip.MustParseAddrPort(pair[0]), netip.MustParseAddrPort(pair[1])
		pkt := udpPacket(t, src, dst, 4000)
		if pkt == nil {
			t.Fatalf("%v: not reassembled", src)
		}
		v, _ := tun.Parse(pkt)
		udp := v.Pkt[v.L3:]
		if v.Proto != 17 || int(binary.BigEndian.Uint16(udp[4:6])) != 4008 || udp[8+3999] != byte(3999%256) {
			t.Fatalf("%v: bad reassembly proto=%d len=%d", src, v.Proto, len(udp))
		}
	}
}

func TestICMPEchoSyntheticForProxied(t *testing.T) {
	r, w, _ := os.Pipe()
	s := &CustomStack{}
	req := make([]byte, 20+8+4)
	req[0], req[8], req[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(req[2:4], uint16(len(req)))
	copy(req[12:16], []byte{172, 19, 0, 1})
	copy(req[16:20], []byte{8, 8, 8, 8})
	req[20] = 8
	binary.BigEndian.PutUint16(req[24:26], 0x1234)
	binary.BigEndian.PutUint16(req[26:28], 7)
	copy(req[28:], "ping")
	v, _ := tun.Parse(req)
	s.handleICMP(w, v)
	w.Close()
	buf := make([]byte, 100)
	n, _ := r.Read(buf)
	rep := buf[:n]
	if n != len(req) || rep[20] != 0 || binary.BigEndian.Uint16(rep[24:26]) != 0x1234 || string(rep[28:32]) != "ping" ||
		netip.AddrFrom4([4]byte(rep[12:16])) != netip.MustParseAddr("8.8.8.8") || tun.CsumFold(tun.CsumAdd(0, rep[20:])) != 0 {
		t.Fatalf("bad echo reply % x", rep)
	}
}

func captureICMP(t *testing.T, f func(s *CustomStack)) []byte {
	t.Helper()
	var got []byte
	old := writeTUNPacketFn
	writeTUNPacketFn = func(_ *os.File, pkt []byte) error { got = append([]byte(nil), pkt...); return nil }
	t.Cleanup(func() { writeTUNPacketFn = old })
	f(&CustomStack{})
	if got == nil {
		t.Fatal("nothing sent")
	}
	return got
}

// udpProbe builds a UDP packet of the given family whose quoted copy must fill
// past the ICMP quote limit.
func udpProbe(fam int, n int) tun.View {
	hl := 20
	if fam == 1 {
		hl = 40
	}
	p := make([]byte, hl+8+n)
	for i := range p {
		p[i] = byte(i*13 + 1)
	}
	if fam == 0 {
		p[0], p[6], p[7], p[9] = 0x45, 0, 0, 17
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	} else {
		p[0], p[6] = 0x60, 17
		binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
	}
	v, ok := tun.Parse(p)
	if !ok {
		panic("probe")
	}
	return v
}

func icmpOutputs(t *testing.T) [][]byte {
	a4, b4 := netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("172.19.0.1")
	a6, b6 := netip.MustParseAddr("2001:db8::9"), netip.MustParseAddr("fdfe::1")
	return [][]byte{
		captureICMP(t, func(s *CustomStack) { s.injectEcho(nil, a4, b4, 0x1234, 0x5678, []byte("ping-data")) }),
		captureICMP(t, func(s *CustomStack) { s.injectEcho(nil, a6, b6, 0x1234, 0x5678, []byte("ping6")) }),
		captureICMP(t, func(s *CustomStack) { s.portUnreachable(nil, udpProbe(0, 1000)) }),
		captureICMP(t, func(s *CustomStack) { s.portUnreachable(nil, udpProbe(1, 1400)) }),
		captureICMP(t, func(s *CustomStack) { s.portUnreachable(nil, udpProbe(0, 40)) }),
	}
}

// TestICMPGolden pins the exact bytes of echo replies and port-unreachable
// messages (IPv4 / IPv6, quoted and truncated); the digests were taken from
// the pre-sendICMP implementation.
func TestICMPGolden(t *testing.T) {
	want := []struct {
		n   int
		sum string
	}{
		{37, "39b8be5b83b4122e810da0a605e2fa774bfc7ed6d069ba4f937d294bb07bc84f"},
		{53, "1aa39a842a661f2eb593d3af333ec104fb54aa1e787c7f86a916de03c8fffa41"},
		{576, "cd2ba824cfcf3d2378ef551f68136a696ec3e8bbb137213326d91f7bc609e224"},
		{1280, "c1bb4c92facb1ad6435e0c91a4ca21e535afcd8037717412c0f176330114bbd8"},
		{96, "f0bcf3c62cd5548be3bb6c1efdfde654297902a73916d553e1638c7437f98a54"},
	}
	for i, p := range icmpOutputs(t) {
		if got := fmt.Sprintf("%x", sha256.Sum256(p)); len(p) != want[i].n || got != want[i].sum {
			t.Errorf("case %d: len=%d sha256=%s, want len=%d %s", i, len(p), got, want[i].n, want[i].sum)
		}
	}
}
