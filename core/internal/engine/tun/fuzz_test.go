package tun

import "testing"

func FuzzParse(f *testing.F) {
	f.Add(make([]byte, 40))
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, ok := Parse(b); ok {
			_, _ = v.Addr(0), v.Addr(1)
		}
	})
}
