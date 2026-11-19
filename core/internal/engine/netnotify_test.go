package engine

import (
	"testing"

	"arc/core/internal/dns"
	"arc/core/internal/engine/udpnat"
	"arc/core/internal/outbound"
)

func TestApplyNetworkChangeSoftKeepsFakeIP(t *testing.T) {
	outbound.ClearEndpointCache()
	dns.GlobalFakeIP.Invalidate()

	ip := dns.GlobalFakeIP.Allocate("soft-handoff.test", false)
	if _, ok := dns.GlobalFakeIP.Lookup(ip); !ok {
		t.Fatal("allocate FakeIP")
	}

	m := udpnat.New()
	GlobalTun.nat.Store(m)
	defer func() { GlobalTun.nat.Store(nil); m.ClearAll() }()

	ApplyNetworkChange(NetChangeSoftLite)

	if _, ok := dns.GlobalFakeIP.Lookup(ip); !ok {
		t.Fatal("soft path must keep FakeIP")
	}
}

func TestApplyNetworkChangeFullWipesFakeIP(t *testing.T) {
	outbound.ClearEndpointCache()
	dns.GlobalFakeIP.Invalidate()
	ip := dns.GlobalFakeIP.Allocate("full-handoff.test", false)
	m := udpnat.New()
	GlobalTun.nat.Store(m)
	defer func() { GlobalTun.nat.Store(nil); m.ClearAll() }()

	ApplyNetworkChange(NetChangeHard)

	if _, ok := dns.GlobalFakeIP.Lookup(ip); ok {
		t.Fatal("full path must invalidate FakeIP")
	}
}

func TestApplyNetworkChangeSoftVsHardContract(t *testing.T) {
	// Soft: FakeIP retained (InvalidateActive path). Hard: FakeIP wiped (ClearEndpointCache + dns.OnNetworkChanged).
	outbound.ClearEndpointCache()
	dns.GlobalFakeIP.Invalidate()
	ipSoft := dns.GlobalFakeIP.Allocate("contract-soft.test", false)
	ApplyNetworkChange(NetChangeSoftLite)
	if _, ok := dns.GlobalFakeIP.Lookup(ipSoft); !ok {
		t.Fatal("soft must keep FakeIP")
	}
	ApplyNetworkChange(NetChangeHard)
	if _, ok := dns.GlobalFakeIP.Lookup(ipSoft); ok {
		t.Fatal("hard must wipe FakeIP")
	}
}

func TestApplyNetworkChangeSoftPathKeepsFakeIP(t *testing.T) {
	outbound.ClearEndpointCache()
	dns.GlobalFakeIP.Invalidate()
	ip := dns.GlobalFakeIP.Allocate("soft-path.test", false)
	m := udpnat.New()
	GlobalTun.nat.Store(m)
	defer func() { GlobalTun.nat.Store(nil); m.ClearAll() }()
	ApplyNetworkChange(NetChangeSoftPath)
	if _, ok := dns.GlobalFakeIP.Lookup(ip); !ok {
		t.Fatal("soft-path must keep FakeIP")
	}
}
