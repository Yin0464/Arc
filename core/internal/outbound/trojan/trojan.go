// Package trojan writes the Trojan session header (a 56-byte hex key, CRLF, a
// command byte, a SOCKS address, CRLF) and frames UDP over the same stream.
package trojan

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
)

const (
	maxLength = 8192
	KeyLength = 56
)

var DefaultALPN = []string{"h2", "http/1.1"}

var crlf = []byte{'\r', '\n'}

type Command = byte

const (
	CommandTCP Command = 1
	CommandUDP Command = 3
)

// AppendHeader appends the session header (key, CRLF, command, SOCKS
// address, CRLF) to buf.
func AppendHeader(buf []byte, hexPassword [KeyLength]byte, command Command, socks5Addr []byte) []byte {
	buf = append(append(append(buf, hexPassword[:]...), crlf...), command)
	return append(append(buf, socks5Addr...), crlf...)
}

func writePacket(w io.Writer, socks5Addr, payload []byte) (int, error) {
	buf := make([]byte, 0, len(socks5Addr)+4+len(payload))
	buf = binary.BigEndian.AppendUint16(append(buf, socks5Addr...), uint16(len(payload)))
	buf = append(append(buf, crlf...), payload...)
	if _, err := w.Write(buf); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func WritePacket(w io.Writer, socks5Addr, payload []byte) (int, error) {
	if len(payload) <= maxLength {
		return writePacket(w, socks5Addr, payload)
	}
	offset := 0
	total := len(payload)
	for offset < total {
		cursor := min(offset+maxLength, total)
		n, err := writePacket(w, socks5Addr, payload[offset:cursor])
		if err != nil {
			return offset + n, err
		}
		offset = cursor
	}
	return total, nil
}

func ReadPacket(r io.Reader, payload []byte) (net.Addr, int, int, error) {
	addr, err := readSocksUDPAddr(r)
	if err != nil {
		return nil, 0, 0, errors.New("read addr error")
	}
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, 0, errors.New("read length/crlf error")
	}
	total := int(binary.BigEndian.Uint16(hdr[:2]))
	if total > maxLength || hdr[2] != '\r' || hdr[3] != '\n' {
		return nil, 0, 0, errors.New("packet invalid")
	}
	length := min(len(payload), total)
	if _, err = io.ReadFull(r, payload[:length]); err != nil {
		return nil, 0, 0, errors.New("read packet error")
	}
	return addr, length, total - length, nil
}

func readSocksUDPAddr(r io.Reader) (net.Addr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return nil, err
	}
	var host string
	var ip net.IP
	switch atyp[0] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return nil, err
		}
		ip = append(net.IP(nil), a[:]...)
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return nil, err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		host = string(b)
	case 4:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return nil, err
		}
		ip = append(net.IP(nil), a[:]...)
	default:
		return nil, errors.New("bad atyp")
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(pb[:]))
	if atyp[0] == 3 {
		return &domainUDPAddr{host: host, port: port}, nil
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}

// domainUDPAddr is a UDP peer carried as SOCKS ATYP 3. The hostname stays on
// this address; net.UDPAddr can only store an IP.
type domainUDPAddr struct {
	host string
	port int
}

func (a *domainUDPAddr) Network() string { return "udp" }

func (a *domainUDPAddr) String() string {
	return net.JoinHostPort(a.host, strconv.Itoa(a.port))
}

type PacketConn struct {
	net.Conn
	remain int
	rAddr  net.Addr
	mux    sync.Mutex // guards the read side (remain, rAddr)
	wMux   sync.Mutex // keeps each written packet's header and payload together
}

func NewPacketConn(conn net.Conn) *PacketConn {
	return &PacketConn{Conn: conn}
}

func (pc *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	pc.wMux.Lock()
	defer pc.wMux.Unlock()
	return WritePacket(pc, SocksAddrBytes(addr), b)
}

func (pc *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	pc.mux.Lock()
	defer pc.mux.Unlock()
	if pc.remain != 0 {
		n, err := pc.Conn.Read(b[:min(len(b), pc.remain)])
		if err != nil {
			return 0, nil, err
		}
		pc.remain -= n
		addr := pc.rAddr
		if pc.remain == 0 {
			pc.rAddr = nil
		}
		return n, addr, nil
	}
	addr, n, remain, err := ReadPacket(pc.Conn, b)
	if err != nil {
		return 0, nil, err
	}
	if remain != 0 {
		pc.remain = remain
		pc.rAddr = addr
	}
	return n, addr, nil
}

func SocksAddrBytes(addr net.Addr) []byte {
	if d, ok := addr.(*domainUDPAddr); ok {
		return socksName(d.host, uint16(d.port))
	}
	if ua, ok := addr.(*net.UDPAddr); ok && ua.IP != nil {
		return socksIP(ua.IP, uint16(ua.Port))
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	p, _ := strconv.Atoi(portStr)
	if ip := net.ParseIP(host); ip != nil {
		return socksIP(ip, uint16(p))
	}
	return socksName(host, uint16(p))
}

// socksIP and socksName build a SOCKS address in one fresh allocation.
func socksIP(ip net.IP, port uint16) []byte {
	atyp, raw := byte(4), ip.To16()
	if v4 := ip.To4(); v4 != nil {
		atyp, raw = 1, v4
	}
	return append(append(append(make([]byte, 0, 3+len(raw)), atyp), raw...), byte(port>>8), byte(port))
}

func socksName(host string, port uint16) []byte {
	return append(append(append(make([]byte, 0, 4+len(host)), 3, byte(len(host))), host...), byte(port>>8), byte(port))
}
