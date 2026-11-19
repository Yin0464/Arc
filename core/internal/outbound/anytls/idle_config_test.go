package anytls

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func noDial(context.Context) (net.Conn, error) { return nil, net.ErrClosed }

// The configured idle timings are used as given, including values at or below
// 5s that the upstream client used to replace with 30s.
func TestNewClientKeepsConfiguredIdleTimings(t *testing.T) {
	var pad atomic.Pointer[PaddingFactory]
	UpdatePaddingScheme(DefaultPaddingScheme, &pad)
	for _, d := range []time.Duration{time.Second, 5 * time.Second, 60 * time.Second} {
		c := NewClient(context.Background(), noDial, &pad, "t", d, d, 0, false)
		got := c.idleSessionTimeout
		c.Close()
		if got != d {
			t.Fatalf("timeout %v became %v", d, got)
		}
	}
}

func TestNewClientRejectsInvalidIdleTimings(t *testing.T) {
	var pad atomic.Pointer[PaddingFactory]
	UpdatePaddingScheme(DefaultPaddingScheme, &pad)
	for name, args := range map[string]struct {
		check, timeout time.Duration
		minIdle        int
	}{
		"zero timeout":     {time.Minute, 0, 0},
		"negative timeout": {time.Minute, -time.Second, 0},
		"zero check":       {0, time.Minute, 0},
		"negative minIdle": {time.Minute, time.Minute, -1},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: accepted", name)
				}
			}()
			c := NewClient(context.Background(), noDial, &pad, "t", args.check, args.timeout, args.minIdle, false)
			c.Close()
		}()
	}
}
