package dns

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"arc/core/internal/dnswire"
)

func TestLANNameUsesUnderlyingDNSOnly(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	go func() {
		b := make([]byte, 1500)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, qt, qe, _ := dnswire.Question(b[:n])
			if qt == dnswire.TypeA {
				pc.WriteTo(dnswire.Answer(b[:n], qe, 0, qt, 60, netip.MustParseAddr("192.168.1.10").AsSlice()), a)
			}
		}
	}()
	calls := stubUpstream(t, netip.MustParseAddr("1.2.4.8"), false)
	defer SetUnderlying("", -1)
	ctx := context.Background()

	list := []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), uint16(pc.LocalAddr().(*net.UDPAddr).Port))}
	sysDNS.Store(&list)
	for _, name := range []string{"router.lan", "printer.local", "nas.home.arpa"} {
		r := Answer(ctx, dnswire.Query(name, dnswire.TypeA))
		if ip, _ := dnswire.FirstIP(r); ip.String() != "192.168.1.10" {
			t.Fatalf("%s: want router answer, got %v (rcode %d)", name, ip, dnswire.Rcode(r))
		}
	}

	sysDNS.Store(nil)
	if r := Answer(ctx, dnswire.Query("printer.lan", dnswire.TypeA)); dnswire.Rcode(r) != 2 {
		t.Fatalf("no underlying DNS: rcode %d, want SERVFAIL", dnswire.Rcode(r))
	}
	if len(*calls) != 0 {
		t.Fatalf("LAN names leaked to DoH: %v", *calls)
	}
}
