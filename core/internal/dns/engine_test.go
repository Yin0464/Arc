package dns

import (
	"context"
	"encoding/binary"
	"testing"

	"arc/core/internal/dnswire"
	"arc/core/internal/router"
)

func TestFastFakeOnlyAddress(t *testing.T) {
	const name = "fast-fake.test"
	router.LearnDomain(name, router.ActionProxy)
	t.Cleanup(router.ClearLearned)

	txt := dnswire.Query(name, 16)
	if _, ok := TryFastFakeIP(txt); ok {
		t.Fatal("TXT took the fake-ip path")
	}
	resp := Answer(context.Background(), txt)
	if len(resp) < 12 || resp[3]&0x0F != 0 || binary.BigEndian.Uint16(resp[6:8]) != 0 {
		t.Fatalf("TXT response %x", resp)
	}
	if _, ok := TryFastFakeIP(dnswire.Query(name, dnswire.TypeA)); !ok {
		t.Fatal("A not faked")
	}
	if _, ok := TryFastFakeIP(dnswire.Query(name, dnswire.TypeAAAA)); !ok {
		t.Fatal("AAAA not faked")
	}
}
