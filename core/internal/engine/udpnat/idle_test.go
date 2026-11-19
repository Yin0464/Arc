package udpnat

import "testing"

func TestUDPIdleTimeouts(t *testing.T) {
	if udpIdle(53) != 20 || udpIdle(443) != 300 || udpIdle(3478) != 60 {
		t.Fatal("idle table")
	}
}
