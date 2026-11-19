package dnswire

import (
	"net/netip"
	"testing"
)

func FuzzWire(f *testing.F) {
	f.Add(Query("example.com", TypeA))
	q := Query("a.cn", TypeAAAA)
	_, _, e, _ := Question(q)
	f.Add(Answer(q, e, 0, TypeAAAA, 60, make([]byte, 16)))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, qt, qEnd, ok := Question(b)
		if ok {
			_ = Answer(b, qEnd, 0, qt, 30, []byte{1, 2, 3, 4})
			_ = d
		}
		_, _ = FirstIP(b)
		_ = MinTTL(b)
		EachIP(b, func(netip.Addr) bool { return true })
		_ = Rcode(b)
		_ = AnswerCount(b)
		_, _ = NegativeTTL(b)
		_ = WithTTL(append([]byte(nil), b...), 5)
	})
}
