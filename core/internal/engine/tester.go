package engine

import (
	"bufio"
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"arc/core/internal/outbound"
	"arc/core/internal/store"
)

var isTestingLock atomic.Bool

var batchGen atomic.Uint64

var (
	batchMu     sync.Mutex
	batchCancel context.CancelFunc
)

type LatencyCallback interface {
	OnStateChanged(isTesting bool)
	OnNodeResult(nodeIdx int, latencyMs int)
}

// BatchProbeConcurrency caps parallel latency probes so a large region cannot
// stampede dials or leak unbounded goroutines.
const BatchProbeConcurrency = 8

const probeHost = "www.gstatic.com"

var http204Probe = []byte("HEAD /generate_204 HTTP/1.1\r\nHost: " + probeHost + "\r\nUser-Agent: Arc\r\nConnection: keep-alive\r\n\r\n")

func CancelBatchTest() {
	batchMu.Lock()
	defer batchMu.Unlock()
	batchGen.Add(1)
	if batchCancel != nil {
		batchCancel()
		batchCancel = nil
	}
	isTestingLock.Store(false)
}

func StartBatchTest(regionIdx int, cb LatencyCallback) {
	// Pin the active catalog pointer for this batch. Load swaps the atomic
	// catalog and leaves prior catalogs immutable; holding *Catalog keeps
	// region/node pointers stable even if a later Load installs a new table.
	cat := store.Get()
	if cb == nil || regionIdx < 0 || regionIdx >= len(cat.Regions) {
		return
	}

	batchMu.Lock()
	if batchCancel != nil {
		batchCancel()
		batchCancel = nil
	}
	gen := batchGen.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	batchCancel = cancel
	isTestingLock.Store(true)
	batchMu.Unlock()

	if batchGen.Load() != gen {
		cancel()
		return
	}
	cb.OnStateChanged(true)

	go func() {
		defer func() {
			batchMu.Lock()
			if batchGen.Load() == gen {
				batchCancel = nil
				isTestingLock.Store(false)
			}
			batchMu.Unlock()
			cancel()
			if batchGen.Load() == gen {
				cb.OnStateChanged(false)
			}
		}()

		region := &cat.Regions[regionIdx]
		var wg sync.WaitGroup
		sem := make(chan struct{}, BatchProbeConcurrency)

		for idx := range region.Nodes {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(nIdx int) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				if ctx.Err() != nil || batchGen.Load() != gen {
					return
				}
				ms := probeUnifiedDelay(ctx, region, &region.Nodes[nIdx])
				if ctx.Err() != nil || batchGen.Load() != gen {
					return
				}
				cb.OnNodeResult(nIdx, ms)
			}(idx)
		}
		wg.Wait()
	}()
}

func probeUnifiedDelay(ctx context.Context, region *store.Region, node *store.Node) int {

	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return -1
		}
		if ms := probeOnce(ctx, region, node); ms >= 0 {
			return ms
		}
	}
	return -1
}

func probeOnce(parent context.Context, region *store.Region, node *store.Node) int {

	ctx, cancel := context.WithTimeout(parent, outbound.ProbeTimeout)
	defer cancel()

	// Cheap TCP precheck through the same probe dial path; dial failure skips HTTP.
	conn, err := outbound.DialNodeProbe(ctx, region, node, outbound.TargetAddr{Domain: probeHost, Port: 80})
	if err != nil {
		return -1
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	br := bufio.NewReader(conn)
	roundTrip := func() bool {
		if _, err := conn.Write(http204Probe); err != nil {
			return false
		}
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodHead})
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusNoContent && !resp.Close
	}
	if !roundTrip() {
		return -1
	}
	start := time.Now()
	if !roundTrip() {
		return -1
	}
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms
}
