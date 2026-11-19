package engine

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The old sync.WaitGroup gate panicked ("WaitGroup is reused before previous
// Wait has returned") when stopCore raced Wait callers on other threads.
func TestShutdownGateConcurrentGoAndWait(t *testing.T) {
	var g ShutdownGate
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					g.Wait()
				}
			}
		}()
	}
	var ran atomic.Int64
	deadline := time.Now().Add(300 * time.Millisecond)
	n := int64(0)
	for time.Now().Before(deadline) {
		g.Go(func() { ran.Add(1) })
		n++
	}
	g.Wait()
	close(stop)
	wg.Wait()
	if ran.Load() != n {
		t.Fatalf("ran %d of %d teardowns", ran.Load(), n)
	}
}

func TestShutdownGateWaitCoversEarlierTeardown(t *testing.T) {
	var g ShutdownGate
	g.Wait() // zero value: no teardown yet
	release := make(chan struct{})
	var order []int
	var mu sync.Mutex
	g.Go(func() { <-release; mu.Lock(); order = append(order, 1); mu.Unlock() })
	g.Go(func() { mu.Lock(); order = append(order, 2); mu.Unlock() })
	waited := make(chan struct{})
	go func() { g.Wait(); close(waited) }()
	select {
	case <-waited:
		t.Fatal("Wait returned before teardown finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-waited
	if len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Fatalf("order %v", order)
	}
}
