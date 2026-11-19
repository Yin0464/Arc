package udpnat

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"arc/core/internal/outbound"
	"arc/core/internal/router"
)

func TestSessionReplyFromAnyTLS(t *testing.T) {
	anchor := netip.MustParseAddrPort("1.1.1.1:443")
	src := netip.MustParseAddrPort("10.0.0.8:50000")
	peer := netip.MustParseAddrPort("8.8.8.8:53")
	s := &udpSession{anchor: anchor}
	got := sessionReplyFrom(s, &outbound.PacketAddr{TargetAddr: outbound.TargetAddr{IP: peer.Addr(), Port: peer.Port()}}, src)
	if got != peer {
		t.Fatalf("packet addr %v", got)
	}
	got = sessionReplyFrom(s, &net.UDPAddr{IP: net.IP(peer.Addr().AsSlice()), Port: int(peer.Port())}, src)
	if got != peer {
		t.Fatalf("udp addr %v", got)
	}
	s.fake = true
	got = sessionReplyFrom(s, &outbound.PacketAddr{TargetAddr: outbound.TargetAddr{IP: peer.Addr(), Port: peer.Port()}}, src)
	if got != anchor {
		t.Fatal("fake-ip session left its anchor")
	}
}

func TestUDPRetireKeepsReplacement(t *testing.T) {
	m := New()
	c1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddrPort("10.0.0.1:1234")
	anchor := netip.MustParseAddrPort("1.2.3.4:53")
	old := newUDPSession(c1, true, false, anchor)
	neu := newUDPSession(c2, true, false, anchor)
	m.mu.Lock()
	m.sessions[natKey{src, natDirect}] = neu
	m.mu.Unlock()
	m.retire(natKey{src, natDirect}, old)
	m.mu.Lock()
	got := m.sessions[natKey{src, natDirect}]
	m.mu.Unlock()
	if got != neu {
		t.Fatal("retire removed the replacement session")
	}
	neu.stop()
	old.stop()
}

func TestUDPOneSessionWhileDialing(t *testing.T) {
	dst := netip.MustParseAddrPort("223.5.5.5:53")
	if router.MatchIP(dst.Addr()) != router.ActionDirect {
		t.Skip("fixture address is not direct")
	}
	m := New()
	defer m.ClearAll()
	src := netip.MustParseAddrPort("10.0.0.8:40000")
	back := func([]byte, netip.AddrPort) {}
	m.ForwardPacket(src, dst, []byte{1, 2}, back)
	m.ForwardPacket(src, dst, []byte{3, 4}, back)
	time.Sleep(100 * time.Millisecond)
	m.mu.Lock()
	sess := m.sessions[natKey{src, natDirect}]
	n := len(m.sessions)
	m.mu.Unlock()
	if n != 1 || sess == nil {
		t.Fatalf("sessions=%d", n)
	}
	sess.mu.Lock()
	ready := sess.conn != nil
	sess.mu.Unlock()
	if !ready {
		t.Fatal("dial did not attach a socket")
	}
	m.ForwardPacket(src, netip.MustParseAddrPort("192.168.1.9:9"), []byte{9}, back)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions[natKey{src, natDirect}] != sess || len(m.sessions) != 1 {
		t.Fatal("lan packet opened a session or replaced the direct one")
	}
}

func TestUDPLanUnicastForwarded(t *testing.T) {
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := echo.ReadFrom(b)
			if err != nil {
				return
			}
			echo.WriteTo(b[:n], a)
		}
	}()
	dst := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	if router.MatchIP(dst.Addr()) != router.ActionLAN {
		t.Fatal("fixture is not LAN")
	}
	m := New()
	defer m.ClearAll()
	got := make(chan netip.AddrPort, 4)
	back := func(p []byte, from netip.AddrPort) {
		if string(p) == "ping" {
			got <- from
		}
	}
	src := netip.MustParseAddrPort("172.19.0.1:40001")
	if m.ForwardPacket(src, dst, []byte("ping"), back) {
		t.Fatal("LAN flow refused")
	}
	select {
	case from := <-got:
		if from != dst {
			t.Fatalf("reply from %v, want %v", from, dst)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no reply: LAN UDP not forwarded")
	}
}

func TestUDPMulticastBroadcastDropped(t *testing.T) {
	m := New()
	defer m.ClearAll()
	src := netip.MustParseAddrPort("172.19.0.1:40002")
	for _, d := range []string{"224.0.0.251:5353", "255.255.255.255:9", "192.168.1.255:9", "[ff02::fb]:5353"} {
		m.ForwardPacket(src, netip.MustParseAddrPort(d), []byte{1}, func([]byte, netip.AddrPort) {})
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) != 0 {
		t.Fatalf("multicast/broadcast opened %d sessions", len(m.sessions))
	}
}

func TestUDPSTUNToDirectIPIsDirect(t *testing.T) {
	dst := netip.MustParseAddrPort("223.5.5.5:3478")
	if router.MatchIP(dst.Addr()) != router.ActionDirect {
		t.Skip("fixture address is not direct")
	}
	m := New()
	defer m.ClearAll()
	src := netip.MustParseAddrPort("172.19.0.1:40003")
	stun := make([]byte, 20)
	stun[1], stun[4], stun[5], stun[6], stun[7] = 1, 0x21, 0x12, 0xA4, 0x42
	m.ForwardPacket(src, dst, stun, func([]byte, netip.AddrPort) {})
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions[natKey{src, natDirect}] == nil || m.sessions[natKey{src, natProxy}] != nil {
		t.Fatal("STUN to a direct IP was not sent direct")
	}
}

func TestUDPRoutesDoNotEvictEachOther(t *testing.T) {
	dst := netip.MustParseAddrPort("223.5.5.5:9000")
	if router.MatchIP(dst.Addr()) != router.ActionDirect {
		t.Skip("fixture address is not direct")
	}
	m := New()
	defer m.ClearAll()
	src := netip.MustParseAddrPort("172.19.0.1:40004")
	back := func([]byte, netip.AddrPort) {}
	m.ForwardPacket(src, dst, []byte{1}, back)
	m.mu.Lock()
	d := m.sessions[natKey{src, natDirect}]
	m.mu.Unlock()
	if d == nil {
		t.Fatal("no direct session")
	}
	m.ForwardPacket(src, netip.MustParseAddrPort("8.8.4.4:9000"), []byte{2}, back)
	m.ForwardPacket(src, dst, []byte{3}, back)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions[natKey{src, natDirect}] != d {
		t.Fatal("proxied datagram evicted the direct session")
	}
}
