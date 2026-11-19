package tun

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestIPv6ExtensionHeaders(t *testing.T) {
	pkt := make([]byte, 40+8+8)
	pkt[0], pkt[6] = 0x60, 0
	binary.BigEndian.PutUint16(pkt[4:6], 16)
	pkt[40], pkt[41] = 17, 0
	binary.BigEndian.PutUint16(pkt[48+4:48+6], 8)
	v, ok := Parse(pkt)
	if !ok || v.Proto != 17 || v.L3 != 48 {
		t.Fatalf("ext header walk: ok=%v proto=%d l3=%d", ok, v.Proto, v.L3)
	}
}

func TestFragmentFlowExpiry(t *testing.T) {
	k := fragKey{proto: 17, id: 99}
	if d, _ := frags.add(k, 0, true, make([]byte, 8), make([]byte, 20)); d != nil {
		t.Fatal("incomplete returned")
	}
	frags.mu.Lock()
	frags.flows[k].started = time.Now().Add(-time.Minute)
	frags.mu.Unlock()
	for i := 0; i < maxFragFlows+2; i++ {
		frags.add(fragKey{proto: 17, id: uint32(1000 + i)}, 0, true, make([]byte, 8), make([]byte, 20))
	}
	frags.mu.Lock()
	n := len(frags.flows)
	frags.mu.Unlock()
	if n > maxFragFlows {
		t.Fatalf("unbounded: %d", n)
	}
}

func TestFragmentOverlapNoInflate(t *testing.T) {
	k := fragKey{proto: 17, id: 42, src: netip.MustParseAddr("1.2.3.4"), dst: netip.MustParseAddr("5.6.7.8")}
	hdr := make([]byte, 20)
	p0 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	p1 := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	if d, _ := frags.add(k, 0, true, p0, hdr); d != nil {
		t.Fatal("incomplete")
	}

	if d, _ := frags.add(k, 0, true, p0, hdr); d != nil {
		t.Fatal("dup incomplete")
	}
	frags.mu.Lock()
	got := frags.flows[k].got
	frags.mu.Unlock()
	if got != 8 {
		t.Fatalf("got=%d after overlap, want 8", got)
	}

	overlap := append([]byte{5, 6, 7, 8}, p1...)
	d, h := frags.add(k, 4, false, overlap, nil)
	if d == nil || h == nil {
		t.Fatal("expected complete")
	}
	want := append(p0, p1...)
	if string(d) != string(want) {
		t.Fatalf("payload %v want %v", d, want)
	}
}

func TestFragmentPastKnownTotalDropped(t *testing.T) {
	r := reassembler{flows: map[fragKey]*fragFlow{}}
	k := fragKey{proto: 17, id: 7}
	if d, _ := r.add(k, 16, false, make([]byte, 8), nil); d != nil {
		t.Fatal("incomplete returned")
	}
	if d, _ := r.add(k, 24, true, make([]byte, 8), nil); d != nil {
		t.Fatal("fragment past the final one was accepted")
	}
	if got := len(r.flows[k].data); got != 24 {
		t.Fatalf("buffer grew to %d past the known total", got)
	}
	d, _ := r.add(k, 0, true, make([]byte, 16), make([]byte, 20))
	if len(d) != 24 {
		t.Fatalf("reassembled %d bytes, want 24", len(d))
	}
}

func TestFinalFragmentShorterThanDataDiscards(t *testing.T) {
	r := reassembler{flows: map[fragKey]*fragFlow{}}
	k := fragKey{proto: 17, id: 8}
	r.add(k, 16, true, make([]byte, 16), nil)
	if d, _ := r.add(k, 8, false, make([]byte, 8), nil); d != nil {
		t.Fatal("inconsistent datagram reassembled")
	}
	if _, ok := r.flows[k]; ok {
		t.Fatal("inconsistent datagram kept in the reassembly table")
	}
}

func v4Frag(id uint16, off int, more bool, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0], pkt[8], pkt[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	fo := uint16(off / 8)
	if more {
		fo |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:8], fo)
	copy(pkt[12:16], []byte{10, 0, 0, 2})
	copy(pkt[16:20], []byte{10, 0, 0, 9})
	copy(pkt[20:], payload)
	return pkt
}

// Fragments whose reassembled payload plus header exceed 65535 bytes are
// dropped, and the flow does not linger.
func TestFragmentReassembledOversizeDropped(t *testing.T) {
	const id = 7777
	if out := reassemble(v4Frag(id, 0, true, make([]byte, 65000))); out != nil {
		t.Fatal("incomplete datagram returned")
	}
	if out := reassemble(v4Frag(id, 65000, false, make([]byte, 528))); out != nil {
		t.Fatalf("oversize datagram returned (%d bytes)", len(out))
	}
	k := fragKey{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.9"), id, 17}
	frags.mu.Lock()
	_, left := frags.flows[k]
	frags.mu.Unlock()
	if left {
		t.Fatal("oversize flow left in the reassembler")
	}
	// A datagram that fits still reassembles.
	reassemble(v4Frag(id+1, 0, true, make([]byte, 64)))
	if out := reassemble(v4Frag(id+1, 64, false, make([]byte, 10))); len(out) != 20+74 {
		t.Fatalf("normal reassembly len=%d", len(out))
	}
}
