package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestHappyEyeballsPrimaryWinsClosesAlt(t *testing.T) {
	primary := netip.MustParseAddr("203.0.113.1")
	altIP := netip.MustParseAddr("203.0.113.2")
	var altClosed atomic.Bool
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}
		if ap.Addr() == primary {
			time.Sleep(30 * time.Millisecond)
			a, b := net.Pipe()
			go b.Close()
			return a, nil
		}
		a, b := net.Pipe()
		go func() {
			<-ctx.Done()
			_ = b.Close()
			altClosed.Store(true)
		}()
		// never completes until cancel
		<-ctx.Done()
		_ = a.Close()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := happyEyeballsTCP(ctx, 5*time.Millisecond, primary,
		func(context.Context) (netip.Addr, error) { return altIP, nil },
		dial, 443)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if altClosed.Load() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHappyEyeballsAltWins(t *testing.T) {
	primary := netip.MustParseAddr("203.0.113.1")
	altIP := netip.MustParseAddr("203.0.113.2")
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		ap, _ := netip.ParseAddrPort(addr)
		if ap.Addr() == primary {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		a, b := net.Pipe()
		go b.Close()
		return a, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := happyEyeballsTCP(ctx, 5*time.Millisecond, primary,
		func(context.Context) (netip.Addr, error) { return altIP, nil },
		dial, 443)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestHappyEyeballsCancel(t *testing.T) {
	primary := netip.MustParseAddr("203.0.113.1")
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := happyEyeballsTCP(ctx, time.Hour, primary,
		func(context.Context) (netip.Addr, error) { return netip.Addr{}, errors.New("no alt") },
		dial, 443)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHappyEyeballsPrimaryFailDoesNotWaitForDelay(t *testing.T) {
	primary := netip.MustParseAddr("203.0.113.1")
	altIP := netip.MustParseAddr("203.0.113.2")
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}
		if ap.Addr() == primary {
			return nil, errors.New("refused")
		}
		a, b := net.Pipe()
		go b.Close()
		return a, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	c, err := happyEyeballsTCP(ctx, time.Hour, primary,
		func(context.Context) (netip.Addr, error) { return altIP, nil },
		dial, 443)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if time.Since(start) > time.Second {
		t.Fatalf("waited %s", time.Since(start))
	}
}

func TestHappyEyeballsDoesNotBlockOnSlowAltLookup(t *testing.T) {
	primary := netip.MustParseAddr("203.0.113.1")
	release := make(chan struct{})
	defer close(release)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}
		if ap.Addr() == primary {
			time.Sleep(30 * time.Millisecond)
		}
		a, b := net.Pipe()
		go b.Close()
		return a, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := happyEyeballsTCP(ctx, time.Millisecond, primary, func(ctx context.Context) (netip.Addr, error) {
			select {
			case <-release:
				return netip.MustParseAddr("203.0.113.9"), nil
			case <-ctx.Done():
				return netip.Addr{}, ctx.Err()
			}
		}, dial, 443)
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("primary success blocked on alt lookup")
	}
}
