package engine

import (
	"sync/atomic"
	"testing"
	"time"

	"arc/core/internal/store"
	"arc/core/internal/store/storetest"
)

type countingLatencyCB struct {
	results atomic.Int32
	starts  atomic.Int32
	stops   atomic.Int32
}

func (c *countingLatencyCB) OnStateChanged(testing bool) {
	if testing {
		c.starts.Add(1)
	} else {
		c.stops.Add(1)
	}
}

func (c *countingLatencyCB) OnNodeResult(nodeIdx int, latencyMs int) {
	c.results.Add(1)
}

func TestCancelBatchTestFreesLockAndDropsLateCallbacks(t *testing.T) {
	storetest.Require(t)
	if len(store.Get().Regions) == 0 || len(store.Get().Regions[0].Nodes) == 0 {
		t.Skip("no regions")
	}
	CancelBatchTest()
	cb := &countingLatencyCB{}
	StartBatchTest(0, cb)

	time.Sleep(10 * time.Millisecond)
	CancelBatchTest()
	deadline := time.Now().Add(2 * time.Second)
	for isTestingLock.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if isTestingLock.Load() {
		t.Fatal("isTestingLock still held after CancelBatchTest")
	}
	afterCancel := cb.results.Load()
	time.Sleep(50 * time.Millisecond)
	if cb.results.Load() != afterCancel {
		t.Fatalf("late OnNodeResult after cancel: before=%d after=%d", afterCancel, cb.results.Load())
	}

	cb2 := &countingLatencyCB{}
	StartBatchTest(0, cb2)
	time.Sleep(5 * time.Millisecond)
	CancelBatchTest()
	deadline = time.Now().Add(2 * time.Second)
	for isTestingLock.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if isTestingLock.Load() {
		t.Fatal("isTestingLock stuck after second cancel")
	}
	if cb2.starts.Load() < 1 {
		t.Fatal("second StartBatchTest did not fire OnStateChanged(true)")
	}
}

func TestStartBatchTestCancelsPrevious(t *testing.T) {
	storetest.Require(t)
	if len(store.Get().Regions) == 0 {
		t.Skip("no regions")
	}
	CancelBatchTest()
	cb1 := &countingLatencyCB{}
	cb2 := &countingLatencyCB{}
	StartBatchTest(0, cb1)
	time.Sleep(5 * time.Millisecond)
	StartBatchTest(0, cb2)
	time.Sleep(20 * time.Millisecond)
	CancelBatchTest()
	deadline := time.Now().Add(2 * time.Second)
	for isTestingLock.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if isTestingLock.Load() {
		t.Fatal("lock held after cancel")
	}
	if cb2.starts.Load() < 1 {
		t.Fatal("replacement batch did not start")
	}
}

func TestBatchProbeConcurrencyCapConstant(t *testing.T) {
	if BatchProbeConcurrency < 1 || BatchProbeConcurrency > 64 {
		t.Fatalf("BatchProbeConcurrency=%d out of sane range", BatchProbeConcurrency)
	}
}

func TestStartBatchTestConcurrencyCancelNoLeak(t *testing.T) {
	storetest.Require(t)
	if len(store.Get().Regions) == 0 || len(store.Get().Regions[0].Nodes) < 2 {
		t.Skip("need multiple nodes")
	}
	CancelBatchTest()
	cb := &countingLatencyCB{}
	StartBatchTest(0, cb)
	time.Sleep(30 * time.Millisecond)
	CancelBatchTest()
	deadline := time.Now().Add(3 * time.Second)
	for isTestingLock.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if isTestingLock.Load() {
		t.Fatal("lock held after cancel — possible goroutine leak under concurrency cap")
	}
}
