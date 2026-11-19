// Package storetest loads a node table for package tests: the one named by
// ARC_NODES when set (a real table, outside the repository), otherwise the
// synthetic fixture in internal/store/testdata that cmd/codegen's tests pin.
package storetest

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"arc/core/internal/store"
)

var (
	once sync.Once
	err  error
)

// Path is the node table tests load.
func Path() string {
	if p := os.Getenv("ARC_NODES"); p != "" {
		return p
	}
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "testdata", "nodes.json")
}

// Load installs the node table once and reports why it is unavailable.
func Load() error {
	once.Do(func() {
		var b []byte
		if b, err = os.ReadFile(Path()); err == nil {
			err = store.Load(b)
		}
	})
	return err
}

// Require loads the node table, skipping t when codegen has not run.
func Require(t testing.TB) {
	t.Helper()
	if err := Load(); err != nil {
		t.Skipf("node table unavailable: %v", err)
	}
}
