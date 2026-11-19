package dns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"arc/core/internal/dnswire"
)

// A query started after ClearCache must not join a flight begun before it;
// it runs its own lookup and gets a fresh answer.
func TestQueryAfterClearDoesNotJoinOldFlight(t *testing.T) {
	const name = "flight-clear.test"
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	withUpstream(t, func(ctx context.Context, q []byte, remote bool) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		_, qt, qEnd, _ := dnswire.Question(q)
		return dnswire.Answer(q, qEnd, 0, qt, 60, []byte{1, 2, 3, 4}), nil
	})
	q := dnswire.Query(name, dnswire.TypeA)
	oldErr := make(chan error, 1)
	go func() {
		_, err := cachedLookup(context.Background(), name, dnswire.TypeA, q, false)
		oldErr <- err
	}()
	<-entered
	ClearCache()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := cachedLookup(ctx, name, dnswire.TypeA, q, false)
	close(release)
	if err != nil {
		t.Fatalf("post-clear query: %v", err)
	}
	if dnswire.AnswerCount(resp) != 1 || calls.Load() != 2 {
		t.Fatalf("answers=%d upstream calls=%d", dnswire.AnswerCount(resp), calls.Load())
	}
	if err := <-oldErr; !errors.Is(err, errCacheCleared) {
		t.Fatalf("pre-clear flight err=%v, want errCacheCleared", err)
	}
	// The old flight finishing must not disturb the fresh answer cached by
	// the post-clear lookup.
	resp, err = cachedLookup(context.Background(), name, dnswire.TypeA, q, false)
	if err != nil || dnswire.AnswerCount(resp) != 1 || calls.Load() != 2 {
		t.Fatalf("cached answer err=%v calls=%d", err, calls.Load())
	}
}
