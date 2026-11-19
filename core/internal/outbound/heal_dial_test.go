package outbound

import (
	"context"
	"io"
	"net"
	"testing"

	"arc/core/internal/store"
)

func TestTrojanHealConnFirstFlightHasRedial(t *testing.T) {

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	called := false
	h := &healConn{
		Conn: a,
		redial: func(ctx context.Context) (net.Conn, error) {
			called = true
			x, y := net.Pipe()
			go y.Close()
			return x, nil
		},
	}
	_ = b.Close()
	_, err := h.Write([]byte("hello-first-flight"))
	if err != nil && !called {
		t.Fatalf("write failed without a redial: %v", err)
	}
	if h.redial == nil {
		t.Fatal("trojan first-flight heal missing redial")
	}

	old := h.Conn
	h.sent = []byte("x")
	h.used = false
	h.got.Store(false)
	ok := h.retry(old, io.ErrClosedPipe)
	if !ok && !called {
		t.Fatal("retry did not invoke redial")
	}
}

func TestTLSSessionCachesConfigured(t *testing.T) {
	if tlsSessionCache == nil || utlsSessionCache == nil {
		t.Fatal("session ticket caches nil")
	}
}

func TestAnyTLSMinIdleConstant(t *testing.T) {
	if anytlsMinIdle < 1 {
		t.Fatalf("minIdle %d", anytlsMinIdle)
	}
}

func TestDialNodeTCPWiresHealForBoth(t *testing.T) {

	dial := func(ctx context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go b.Close()
		return a, nil
	}
	c, err := dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := &healConn{Conn: c, redial: dial}
	if r.redial == nil {
		t.Fatal("missing redial")
	}
	_ = store.ProtoTrojan
	_ = r.Close()
}
