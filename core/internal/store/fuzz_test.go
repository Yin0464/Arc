package store

import (
	"os"
	"testing"
)

func FuzzParse(f *testing.F) {
	if b, err := os.ReadFile("testdata/nodes.json"); err == nil {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := Parse(b); err == nil && c != nil {
			_ = c.UIJSON()
		}
	})
}
