package dnswire

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	q := Query("Example.COM", TypeA)
	d, qt, qEnd, ok := Question(q)
	if !ok || d != "example.com" || qt != TypeA || qEnd != len(q) {
		t.Fatal(d, qt, qEnd, ok)
	}
	a := Answer(q, qEnd, 0, TypeA, 30, []byte{1, 2, 3, 4})
	if ip, err := FirstIP(a); err != nil || ip.String() != "1.2.3.4" || MinTTL(a) != 30 {
		t.Fatal(ip, err)
	}

	c := append(append([]byte{}, a[:12]...), 0xC0, 0x0C, 0, 1, 0, 1)
	c = append(c, a[qEnd:]...)
	if ip, err := FirstIP(c); err != nil || ip.String() != "1.2.3.4" {
		t.Fatal("compressed", ip, err)
	}
	if sf := Answer(q, qEnd, 2, 0, 0, nil); sf[3]&0xF != 2 || sf[7] != 0 {
		t.Fatal("servfail")
	}
}

func TestRace(t *testing.T) {
	v, err := Race(context.Background(), time.Second, 3, func(ctx context.Context, i int) (int, error) {
		if i != 2 {
			return 0, errors.New("x")
		}
		return 7, nil
	})
	if v != 7 || err != nil {
		t.Fatal(v, err)
	}
}
