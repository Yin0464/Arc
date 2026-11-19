package ustack

import (
	"testing"
	"time"
)

func TestDelayedAckSchedulesAndFlushes(t *testing.T) {
	st := &Stack{}
	st.closed.Store(true)
	c := &tcpConn{
		mss:    usDefaultMSS,
		rwait:  make(chan struct{}, 1),
		swait:  make(chan struct{}, 1),
		st:     st,
		state:  stEstablished,
		lastRx: time.Now(),
		rto:    time.Hour,
	}
	c.scheduleAckLocked(100, false)
	if !c.delayedAck || c.delAckBytes != 100 {
		t.Fatalf("delayedAck=%v bytes=%d", c.delayedAck, c.delAckBytes)
	}
	if c.delAckAt.IsZero() {
		t.Fatal("delAckAt unset")
	}
	c.delAckAt = time.Now().Add(-time.Millisecond)
	c.onTick(time.Now())
	if c.delayedAck {
		t.Fatal("delayed ACK should flush on tick")
	}
}

func TestDelayedAckEveryTwoMSSImmediate(t *testing.T) {
	st := &Stack{}
	st.closed.Store(true)
	c := &tcpConn{
		mss:   1000,
		rwait: make(chan struct{}, 1),
		swait: make(chan struct{}, 1),
		st:    st,
	}
	c.scheduleAckLocked(1000, false)
	if !c.delayedAck {
		t.Fatal("first MSS should delay")
	}
	c.scheduleAckLocked(1000, false)
	if c.delayedAck || c.delAckBytes != 0 {
		t.Fatalf("2*MSS should ACK immediately, delayed=%v bytes=%d", c.delayedAck, c.delAckBytes)
	}
}

func TestUsDelAckConstant(t *testing.T) {
	if usDelAck != 40*time.Millisecond {
		t.Fatalf("usDelAck=%v", usDelAck)
	}
	if usDelAckSegs != 2 {
		t.Fatalf("usDelAckSegs=%d", usDelAckSegs)
	}
}
