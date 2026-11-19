package engine

import (
	"arc/core/internal/engine/tun"
	"net/netip"
	"os"
	"testing"
)

func verify(t *testing.T, pkt []byte) {
	t.Helper()
	v, ok := tun.Parse(pkt)
	if !ok {
		t.Fatal("parse")
	}
	l4 := v.Pkt[v.L3:]
	sum := tun.CsumAdd(tun.CsumAdd(tun.CsumAdd(uint32(v.Proto)+uint32(len(l4)), v.Pkt[v.AOff:v.AOff+v.ALen]), v.Pkt[v.AOff+v.ALen:v.AOff+2*v.ALen]), l4)
	if tun.CsumFold(sum) != 0 {
		t.Fatalf("l4 checksum bad")
	}
	if v.Fam == 0 && tun.CsumFold(tun.CsumAdd(0, pkt[:20])) != 0 {
		t.Fatal("ip checksum bad")
	}
}

func TestWriteUDPChecksum(t *testing.T) {
	for _, pair := range [][2]string{{"8.8.8.8:53", "172.19.0.1:999"}, {"[2001:db8::1]:53", "[fdfe:dcba:9876::1]:999"}} {
		f, _ := os.CreateTemp(t.TempDir(), "pkt")
		writeUDP(GlobalTun, f, netip.MustParseAddrPort(pair[0]), netip.MustParseAddrPort(pair[1]), []byte("hello"))
		f.Close()
		b, _ := os.ReadFile(f.Name())
		verify(t, b)
	}
}
