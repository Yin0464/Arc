package outbound

import (
	"net"
	"testing"
	"time"
)

func TestTouchSessionRefreshesLiveConn(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	lc := TrackConn(a).(*liveConn)
	defer lc.Close()
	old := time.Now().Add(-time.Minute).UnixNano()
	lc.last.Store(old)
	touchSession(&sessConn{Conn: lc})
	if lc.last.Load() <= old {
		t.Fatal("reused session timestamp not refreshed")
	}
	closeStale(10 * time.Second)
	liveMu.Lock()
	_, ok := live[lc]
	liveMu.Unlock()
	if !ok {
		t.Fatal("closeStale closed a freshly reused session")
	}
}
