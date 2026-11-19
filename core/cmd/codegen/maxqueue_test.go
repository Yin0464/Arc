package main

import (
	"math/rand/v2"
	"path/filepath"
	"testing"
)

// naivePop is the original O(n) scan: first index with the most kids, then
// swap-remove. maxQueue must pick exactly the same node every time.
func naivePop(q []*datNode) (*datNode, []*datNode) {
	bi := 0
	for i := 1; i < len(q); i++ {
		if len(q[i].kids) > len(q[bi].kids) {
			bi = i
		}
	}
	n := q[bi]
	q[bi] = q[len(q)-1]
	return n, q[:len(q)-1]
}

func TestMaxQueueMatchesNaiveScan(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	mk := func() *datNode { return &datNode{kids: make([]string, r.IntN(5))} }
	const total = 5000
	q := newMaxQueue(total)
	var ref []*datNode
	pushed := 0
	for pushed < total || len(ref) > 0 {
		if pushed < total && (len(ref) == 0 || r.IntN(3) > 0) {
			n := mk()
			q.push(n)
			ref = append(ref, n)
			pushed++
			continue
		}
		var want *datNode
		want, ref = naivePop(ref)
		if got := q.popFirstMax(); got != want {
			t.Fatalf("pop order diverged after %d pushes", pushed)
		}
		if q.len() != len(ref) {
			t.Fatalf("len %d want %d", q.len(), len(ref))
		}
	}
}

func TestReadLinesMissingFileFails(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("missing rule-library file must fail the build, not fetch or return nil")
		}
	}()
	readLines(filepath.Join(t.TempDir(), "geoip_cn.txt"))
}
