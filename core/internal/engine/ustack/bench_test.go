package ustack

import (
	"arc/core/internal/engine/tun"
	"net/netip"
	"os"
	"sync"
	"testing"
)

func BenchmarkTunEmitParallel(b *testing.B) {
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Skip(err)
	}
	defer devnull.Close()
	var mu sync.Mutex
	w := tun.NewWriter(devnull, tun.WQueue, &mu, func(pkt []byte) { _ = tun.WritePacket(devnull, pkt) })
	defer w.Shutdown()
	u := &Stack{cfg: Config{Send: func(pkt []byte, pooled *[]byte) { w.Enqueue(tun.Packet{Pkt: pkt, Pooled: pooled}) }}}
	src := netip.MustParseAddrPort("198.18.0.1:443")
	dst := netip.MustParseAddrPort("172.19.0.1:40000")
	payload := make([]byte, 1380)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.SetParallelism(4)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			u.emitTCP(0, src, dst, 1, 1, 0x18, 1024, nil, payload)
		}
	})
	b.StopTimer()
}

func BenchmarkSendPath(b *testing.B) {
	c := newTestConn(nil)
	data := make([]byte, usDefaultMSS)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = c.Write(data)
		c.handleSeg(c.rcvNxt, c.sndNxt, 0x10, 65535, nil, nil)
	}
}
