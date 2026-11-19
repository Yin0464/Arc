package engine

import (
	"arc/core/internal/dns"
	"arc/core/internal/outbound"
)

// The orchestrator owns the dns -> outbound edge: dns only sees the DoH racer.
func init() { dns.SetDoH(outbound.DoHRacer{}) }
