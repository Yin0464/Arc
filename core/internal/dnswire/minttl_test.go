package dnswire

import (
	"encoding/binary"
	"testing"
)

func negResp(name string, qtype uint16, rcode byte, soaTTL, soaMin uint32) []byte {
	w := Query(name, qtype)
	w[2], w[3] = 0x81, 0x80|rcode
	binary.BigEndian.PutUint16(w[8:], 1)
	w = append(w, 0xC0, 12, 0, 6, 0, 1)
	w = binary.BigEndian.AppendUint32(w, soaTTL)
	rdata := []byte{0, 0}
	for _, v := range []uint32{1, 7200, 900, 1209600, soaMin} {
		rdata = binary.BigEndian.AppendUint32(rdata, v)
	}
	w = binary.BigEndian.AppendUint16(w, uint16(len(rdata)))
	return append(w, rdata...)
}

func posResp(name string, ttls ...uint32) []byte {
	q := Query(name, TypeA)
	_, _, qEnd, _ := Question(q)
	w := Answer(q, qEnd, 0, TypeA, ttls[0], []byte{1, 2, 3, 4})
	for _, t := range ttls[1:] {
		binary.BigEndian.PutUint16(w[6:], binary.BigEndian.Uint16(w[6:])+1)
		w = append(w, 0xC0, 12, 0, 1, 0, 1)
		w = binary.BigEndian.AppendUint32(w, t)
		w = append(w, 0, 4, 5, 6, 7, 8)
	}
	return w
}

func TestMinTTLCurrentBehaviour(t *testing.T) {
	if got := MinTTL(posResp("a.example", 300, 120)); got != 120 {
		t.Fatalf("positive min=%d", got)
	}
	if got := MinTTL(negResp("a.example", TypeAAAA, 0, 3600, 600)); got != 0 {
		t.Fatalf("NOERROR-empty=%d", got)
	}
	if got := MinTTL(negResp("a.example", TypeA, 3, 3600, 600)); got != 0 {
		t.Fatalf("NXDOMAIN=%d", got)
	}
	if got := MinTTL([]byte{1, 2, 3}); got != 0 {
		t.Fatalf("malformed=%d", got)
	}
}

func TestNegativeTTLAndWithTTL(t *testing.T) {
	if v, ok := NegativeTTL(negResp("a.example", TypeAAAA, 0, 3600, 600)); !ok || v != 600 {
		t.Fatalf("neg=%d %v", v, ok)
	}
	if v, ok := NegativeTTL(negResp("a.example", TypeA, 3, 45, 600)); !ok || v != 45 {
		t.Fatalf("neg soa ttl=%d %v", v, ok)
	}
	if _, ok := NegativeTTL(posResp("a.example", 300)); ok {
		t.Fatal("positive has no SOA")
	}
	w := WithTTL(posResp("a.example", 300, 120), 7)
	if MinTTL(w) != 7 {
		t.Fatal("WithTTL")
	}
	if FirstIP(w); Rcode(w) != 0 || AnswerCount(w) != 2 {
		t.Fatal("header")
	}
}

// A record whose rdata runs past the message end is left untouched, like
// eachRR and NegativeTTL treat it.
func TestWithTTLTruncatedRecord(t *testing.T) {
	full := posResp("a.example", 300, 120)
	trunc := full[:len(full)-2] // second answer's rdata cut short
	w := WithTTL(trunc, 7)
	if len(w) != len(trunc) {
		t.Fatalf("len %d -> %d", len(trunc), len(w))
	}
	first := len(full) - 32 + 6 // TTL of the first answer
	if got := binary.BigEndian.Uint32(w[first:]); got != 7 {
		t.Fatalf("first TTL=%d want 7", got)
	}
	if got := binary.BigEndian.Uint32(w[len(full)-10:]); got != 120 {
		t.Fatalf("truncated record TTL rewritten to %d", got)
	}
}

// A reserved label type (high bits 01 or 10) ends the name walk: the record
// is rejected instead of being skipped as a 64..191-byte label.
func TestReservedLabelTypeRejected(t *testing.T) {
	q := Query("a.example", TypeA)
	_, _, qEnd, _ := Question(q)
	for _, l := range []byte{0x41, 0x81} {
		w := append([]byte(nil), q[:qEnd]...)
		w[2], w[3], w[7] = 0x81, 0x80, 1
		w = append(w, l)
		w = append(w, make([]byte, int(l))...) // where a bogus skip would land
		w = append(w, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 4, 9, 9, 9, 9)
		if ip, err := FirstIP(w); err == nil {
			t.Fatalf("label %#x: parsed bogus answer %v", l, ip)
		}
		if got := MinTTL(w); got != 0 {
			t.Fatalf("label %#x: MinTTL=%d", l, got)
		}
		if out := WithTTL(w, 7); string(out) != string(w) {
			t.Fatalf("label %#x: WithTTL rewrote a malformed record", l)
		}
	}
}
