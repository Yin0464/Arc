package outbound

import (
	"testing"

	"arc/core/internal/dnswire"
)

func TestWithECS(t *testing.T) {
	q := dnswire.Query("m.baidu.com", dnswire.TypeA)
	e := WithECS(q)
	if e[11] != 1 || len(e) != len(q)+22 {
		t.Fatalf("bad OPT: %x", e)
	}
	if d, qt, _, ok := dnswire.Question(e); !ok || d != "m.baidu.com" || qt != dnswire.TypeA {
		t.Fatal("question changed")
	}
	if len(WithECS(e)) != len(e) {
		t.Fatal("double OPT")
	}
}
