package outbound

import (
	"testing"
	"time"
)

func TestHappyEyeballsStaleDelay250ms(t *testing.T) {
	if epDiskDialTimeout != 250*time.Millisecond {
		t.Fatalf("epDiskDialTimeout=%v want 250ms", epDiskDialTimeout)
	}
}
