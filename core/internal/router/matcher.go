package router

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

type Action uint8

const (
	ActionUnknown Action = 0
	ActionProxy   Action = 1
	ActionDirect  Action = 2
	ActionLAN     Action = 3
)

func MatchDomain(domain string) Action {
	domain = CleanLowerDomain(domain)
	if IsLANDomain(domain) {
		return ActionLAN
	}
	if IsCarrierDomain(domain) {
		return ActionDirect
	}
	switch domTag(domain) {
	case tagForeign:
		return ActionProxy
	case tagCN:
		return ActionDirect
	}
	if act, ok := lookupLearned(domain); ok {
		return act
	}
	return ActionUnknown
}

func IsLANDomain(domain string) bool {
	domain = CleanLowerDomain(domain)
	return strings.HasSuffix(domain, ".lan") || strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".arpa")
}

func IsCNDomain(domain string) bool { return IsCarrierDomain(domain) || domTag(domain) == tagCN }

func IsGoogleIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		return ipTag4(binary.BigEndian.Uint32(b[:])) == tagForeign
	}
	b := addr.As16()
	return addr.Is6() && ipTag6(binary.BigEndian.Uint64(b[:8])) == tagForeign
}

func MatchIP(addr netip.Addr) Action {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return ActionLAN
	}
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 10 || b[0] == 127 || b[0] == 0 || b[0] >= 224 ||
			(b[0] == 192 && b[1] == 168) ||
			(b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
			(b[0] == 100 && b[1] >= 64 && b[1] <= 127) ||
			(b[0] == 169 && b[1] == 254) {
			return ActionLAN
		}
		switch ipTag4(binary.BigEndian.Uint32(b[:])) {
		case tagForeign:
			return ActionProxy
		case tagCN:
			return ActionDirect
		}
		return ActionProxy
	}

	b16 := addr.As16()
	if addr.IsLoopback() || b16[0] == 0xff || (b16[0] == 0xfe && (b16[1]&0xc0) == 0x80) || (b16[0]&0xfe) == 0xfc {
		return ActionLAN
	}
	switch ipTag6(binary.BigEndian.Uint64(b16[:8])) {
	case tagForeign:
		return ActionProxy
	case tagCN:
		return ActionDirect
	}
	return ActionProxy
}

func CleanLowerDomain(s string) string {
	s = strings.TrimSuffix(s, ".")
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return strings.ToLower(s)
		}
	}
	return s
}

// ResolveIPAction is MatchIP with the learned-direct override: a MatchIP proxy
// hit that IsDirectIP still treats as direct.
func ResolveIPAction(addr netip.Addr) Action {
	act := MatchIP(addr)
	if act == ActionProxy && IsDirectIP(addr) {
		return ActionDirect
	}
	return act
}

// IsDirectOrLAN reports whether act is a non-proxy local/direct verdict.
func IsDirectOrLAN(act Action) bool {
	return act == ActionDirect || act == ActionLAN
}
