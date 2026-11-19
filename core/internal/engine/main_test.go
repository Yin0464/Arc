package engine

import (
	"os"
	"testing"

	"arc/core/internal/store/storetest"
)

// The node table used to be compiled in; keep tests on real nodes when the
// codegen output is present.
func TestMain(m *testing.M) {
	_ = storetest.Load()
	os.Exit(m.Run())
}
