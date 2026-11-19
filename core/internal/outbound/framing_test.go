package outbound

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"

	"arc/core/internal/outbound/anytls"
	"arc/core/internal/outbound/trojan"
)

func TestAppendAddrSOCKS5(t *testing.T) {
	b := appendAddr(nil, TargetAddr{Domain: "example.com", Port: 443})
	if b[0] != 3 || b[1] != byte(len("example.com")) {
		t.Fatalf("domain atyp: %v", b[:2])
	}
	if string(b[2:2+len("example.com")]) != "example.com" {
		t.Fatal("domain")
	}
	if binary.BigEndian.Uint16(b[len(b)-2:]) != 443 {
		t.Fatal("port")
	}
	b4 := appendAddr(nil, TargetAddr{IP: netip.MustParseAddr("1.2.3.4"), Port: 80})
	if b4[0] != 1 || !bytes.Equal(b4[1:5], []byte{1, 2, 3, 4}) || binary.BigEndian.Uint16(b4[5:]) != 80 {
		t.Fatalf("ipv4: %v", b4)
	}
}

func TestTrojanAppendHeader(t *testing.T) {
	var key [trojan.KeyLength]byte
	for i := range key {
		key[i] = 'a'
	}
	addr := appendAddr(nil, TargetAddr{Domain: "x.test", Port: 443})
	got := trojan.AppendHeader(nil, key, trojan.CommandTCP, addr)
	if !bytes.Equal(got[:56], key[:]) {
		t.Fatal("key")
	}
	if got[56] != '\r' || got[57] != '\n' || got[58] != trojan.CommandTCP {
		t.Fatalf("crlf/cmd: %v", got[56:59])
	}
	if !bytes.HasSuffix(got, []byte{'\r', '\n'}) {
		t.Fatal("trailing crlf")
	}
}

func TestTrojanUDPPacketRoundTrip(t *testing.T) {
	payload := []byte("hello-udp")
	addr := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	var buf bytes.Buffer
	n, err := trojan.WritePacket(&buf, trojan.SocksAddrBytes(addr), payload)
	if err != nil || n != len(payload) {
		t.Fatalf("write %d %v", n, err)
	}
	out := make([]byte, 64)
	ra, rn, remain, err := trojan.ReadPacket(bytes.NewReader(buf.Bytes()), out)
	if err != nil || rn != len(payload) || remain != 0 {
		t.Fatalf("read n=%d remain=%d err=%v", rn, remain, err)
	}
	if !bytes.Equal(out[:rn], payload) {
		t.Fatal("payload")
	}
	ua := ra.(*net.UDPAddr)
	if !ua.IP.Equal(net.IPv4(8, 8, 8, 8)) || ua.Port != 53 {
		t.Fatalf("addr %v", ua)
	}
}

func TestTrojanUDPDomainNotDiscarded(t *testing.T) {
	payload := []byte("q")
	for _, host := range []string{"dns.example", "8.8.8.8"} {
		raw := append(append([]byte{3, byte(len(host))}, host...), 0, 53)
		var buf bytes.Buffer
		if _, err := trojan.WritePacket(&buf, raw, payload); err != nil {
			t.Fatal(err)
		}
		ra, n, remain, err := trojan.ReadPacket(bytes.NewReader(buf.Bytes()), make([]byte, 8))
		if err != nil || n != len(payload) || remain != 0 {
			t.Fatalf("%s: n=%d remain=%d err=%v", host, n, remain, err)
		}
		if _, ok := ra.(*net.UDPAddr); ok {
			t.Fatalf("%s: domain atyp became an IP address %v", host, ra)
		}
		if got := trojan.SocksAddrBytes(ra); !bytes.Equal(got, raw) {
			t.Fatalf("%s: hostname discarded, reencoded %v want %v (%s)", host, got, raw, ra)
		}
	}
}

func TestAnyTLSFrameHeader(t *testing.T) {

	hdr := make([]byte, 7)
	hdr[0] = 2
	binary.BigEndian.PutUint32(hdr[1:5], 7)
	binary.BigEndian.PutUint16(hdr[5:7], 3)
	if hdr[0] != 2 || binary.BigEndian.Uint32(hdr[1:5]) != 7 || binary.BigEndian.Uint16(hdr[5:7]) != 3 {
		t.Fatal(hdr)
	}
}

func TestAnyTLSPaddingSchemeDefault(t *testing.T) {
	p := anytls.NewPaddingFactory(anytls.DefaultPaddingScheme)
	if p == nil || p.Stop != 8 {
		t.Fatalf("factory %#v", p)
	}
	sizes := p.GenerateRecordPayloadSizes(0)
	if len(sizes) != 1 || sizes[0] != 30 {
		t.Fatalf("pkt0 sizes %v", sizes)
	}
}

func TestUoTAddrRoundTrip(t *testing.T) {
	in := TargetAddr{Domain: "dns.google", Port: 53}
	b := appendUoTAddr(nil, in)
	if b[0] != 2 {
		t.Fatal("fqdn atyp")
	}
	out, err := readUoTAddr(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if out.Domain != in.Domain || out.Port != in.Port {
		t.Fatalf("%+v", out)
	}
	ip := TargetAddr{IP: netip.MustParseAddr("2001:db8::1"), Port: 443}
	b = appendUoTAddr(nil, ip)
	if b[0] != 1 {
		t.Fatal("ipv6 atyp")
	}
	out, err = readUoTAddr(bytes.NewReader(b))
	if err != nil || out.IP != ip.IP || out.Port != 443 {
		t.Fatalf("%+v %v", out, err)
	}
	_ = io.EOF
}

func TestSocksMagicUoTV2(t *testing.T) {
	b := appendSocksDomain(nil, uotMagicV2, 0)
	if b[0] != 3 || string(b[2:2+len(uotMagicV2)]) != uotMagicV2 {
		t.Fatal(b)
	}
}

func TestSocksAddrBytesFreshSingleAlloc(t *testing.T) {
	backing := []byte{9, 9, 9, 9, 0xAA, 0xBB, 0xCC, 0xDD}
	v4 := &net.UDPAddr{IP: net.IP(backing[:4]), Port: 0x1234} // spare capacity after the IP
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53}
	mapped := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 80}
	cases := []struct {
		addr net.Addr
		want []byte
	}{
		{v4, []byte{1, 9, 9, 9, 9, 0x12, 0x34}},
		{v6, append(append([]byte{4}, net.ParseIP("2001:db8::1")...), 0, 53)},
		{mapped, []byte{1, 1, 2, 3, 4, 0, 80}},
		{&net.TCPAddr{IP: net.ParseIP("5.6.7.8"), Port: 443}, []byte{1, 5, 6, 7, 8, 1, 0xBB}},
	}
	for _, c := range cases {
		if got := trojan.SocksAddrBytes(c.addr); !bytes.Equal(got, c.want) {
			t.Fatalf("%v: got %v want %v", c.addr, got, c.want)
		}
	}
	if !bytes.Equal(backing, []byte{9, 9, 9, 9, 0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Fatalf("caller IP backing array mutated: %v", backing)
	}
	for _, a := range []net.Addr{v4, v6, mapped} {
		if n := testing.AllocsPerRun(100, func() { _ = trojan.SocksAddrBytes(a) }); n != 1 {
			t.Fatalf("%v: %v allocs, want 1", a, n)
		}
	}
}

type recConn struct {
	net.Conn
	writes [][]byte
	rd     *bytes.Reader
}

func (c *recConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}
func (c *recConn) Read(b []byte) (int, error) { return c.rd.Read(b) }

func TestUoTRequestHeaderOnce(t *testing.T) {
	dest := TargetAddr{Domain: "example.com", Port: 443}
	req := appendUoTAddr([]byte{0}, dest)
	frame := func(p string) []byte {
		return append(binary.BigEndian.AppendUint16(appendUoTAddr(nil, dest), uint16(len(p))), p...)
	}
	// WriteTo first: header + first frame in one write, then frames only.
	rc := &recConn{}
	u := newUoTConn(rc, dest)
	for _, p := range []string{"a", "bc"} {
		if n, err := u.WriteTo([]byte(p), &PacketAddr{dest}); err != nil || n != len(p) {
			t.Fatalf("WriteTo: n=%d err=%v", n, err)
		}
	}
	if len(rc.writes) != 2 || !bytes.Equal(rc.writes[0], append(append([]byte(nil), req...), frame("a")...)) ||
		!bytes.Equal(rc.writes[1], frame("bc")) {
		t.Fatalf("WriteTo writes: %v", rc.writes)
	}
	// ReadFrom first: the header goes out alone, exactly once.
	rc = &recConn{rd: bytes.NewReader(append(frame("x"), frame("y")...))}
	u = newUoTConn(rc, dest)
	buf := make([]byte, 8)
	for _, want := range []string{"x", "y"} {
		n, _, err := u.ReadFrom(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("ReadFrom: %q err=%v", buf[:n], err)
		}
	}
	if len(rc.writes) != 1 || !bytes.Equal(rc.writes[0], req) {
		t.Fatalf("ReadFrom writes: %v", rc.writes)
	}
}

type discardConn struct{ net.Conn }

func (discardConn) Write(b []byte) (int, error) { return len(b), nil }

// The lazy Trojan header goes out once: with the first payload in one write, or
// alone ahead of the first Read; building it costs one allocation.
func TestTrojanLazyHeaderOnce(t *testing.T) {
	var key [trojan.KeyLength]byte
	addr := appendAddr(nil, TargetAddr{Domain: "x.test", Port: 443})
	hdr := trojan.AppendHeader(nil, key, trojan.CommandTCP, addr)
	rc := &recConn{}
	c := &trojanLazy{Conn: rc, key: key, cmd: trojan.CommandTCP, addr: addr}
	for _, p := range []string{"first", "second"} {
		if n, err := c.Write([]byte(p)); err != nil || n != len(p) {
			t.Fatalf("Write: n=%d err=%v", n, err)
		}
	}
	if len(rc.writes) != 2 || !bytes.Equal(rc.writes[0], append(append([]byte(nil), hdr...), "first"...)) ||
		string(rc.writes[1]) != "second" {
		t.Fatalf("writes: %q", rc.writes)
	}
	rc = &recConn{rd: bytes.NewReader([]byte("r"))}
	c = &trojanLazy{Conn: rc, key: key, cmd: trojan.CommandTCP, addr: addr}
	if _, err := c.Read(make([]byte, 1)); err != nil || len(rc.writes) != 1 || !bytes.Equal(rc.writes[0], hdr) {
		t.Fatalf("Read-first header: %q err=%v", rc.writes, err)
	}
	p := make([]byte, 512)
	cs := make([]trojanLazy, 101)
	i := 0
	if n := testing.AllocsPerRun(100, func() {
		cs[i] = trojanLazy{Conn: discardConn{}, addr: addr}
		_, _ = cs[i].Write(p)
		i++
	}); n != 1 {
		t.Fatalf("first write: %v allocs, want 1", n)
	}
}

// appendAddr appends after a caller's prefix and, from nil, encodes in one
// allocation.
func TestAppendAddrPrefixAndSingleAlloc(t *testing.T) {
	addrs := []TargetAddr{
		{Domain: "www.example.com", Port: 443},
		{IP: netip.MustParseAddr("1.2.3.4"), Port: 80},
		{IP: netip.MustParseAddr("2001:db8::1"), Port: 53},
	}
	for _, a := range addrs {
		plain := appendAddr(nil, a)
		if got := appendAddr([]byte{0xEE, 0xFF}, a); !bytes.Equal(got, append([]byte{0xEE, 0xFF}, plain...)) {
			t.Fatalf("%v: prefix lost: %v", a, got)
		}
		if n := testing.AllocsPerRun(100, func() { _ = appendAddr(nil, a) }); n != 1 {
			t.Fatalf("%v: %v allocs, want 1", a, n)
		}
	}
}
