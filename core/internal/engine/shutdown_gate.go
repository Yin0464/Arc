package engine

import "sync"

// ShutdownGate orders core teardown against later JNI entry points. Go runs a
// teardown after every earlier one; Wait blocks until all of them finished.
// Unlike sync.WaitGroup it is safe to call Go and Wait concurrently.
type ShutdownGate struct {
	mu   sync.Mutex
	done chan struct{}
}

// Go starts f in the background after the previous teardown completes.
func (g *ShutdownGate) Go(f func()) {
	done := make(chan struct{})
	g.mu.Lock()
	prev := g.done
	g.done = done
	g.mu.Unlock()
	go func() {
		defer close(done)
		if prev != nil {
			<-prev
		}
		f()
	}()
}

// Wait returns once every teardown started before the call has finished.
func (g *ShutdownGate) Wait() {
	g.mu.Lock()
	c := g.done
	g.mu.Unlock()
	if c != nil {
		<-c
	}
}
