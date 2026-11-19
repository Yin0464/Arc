package engine

import (
	"arc/core/internal/dns"
	"arc/core/internal/engine/udpnat"
	"arc/core/internal/outbound"
)

const softUDPIdleEvictSec = int64(15)

const (
	NetChangeSoftLite = 0
	NetChangeHard     = 1
	NetChangeSoftPath = 2
)

func ApplyNetworkChange(kind int) {
	if kind == NetChangeHard {
		outbound.ClearEndpointCache()
		dns.OnNetworkChanged()
		GlobalTun.ResetUDP()
		return
	}
	outbound.InvalidateActive()
	dns.ClearCache()
	if kind == NetChangeSoftPath {
		GlobalTun.ResetUDP()
		return
	}
	GlobalTun.ResetUDPIdle(udpnat.SessionLimit, softUDPIdleEvictSec)
}
