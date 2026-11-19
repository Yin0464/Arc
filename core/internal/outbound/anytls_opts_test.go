package outbound

import (
	"testing"
	"time"

	"arc/core/internal/outbound/anytls"
	"arc/core/internal/store"
)

func TestAnyTLSPoolParamsDefaultsWhenUnset(t *testing.T) {
	pad, meta, check, timeout, minIdle := anytlsPoolParams(&store.NodeOpts{})
	if string(pad) != string(anytls.DefaultPaddingScheme) {
		t.Fatal("padding default")
	}
	if meta != "" {
		t.Fatalf("meta=%q", meta)
	}
	if check != anytlsIdleCheck || timeout != anytlsIdleTimeout || minIdle != anytlsMinIdle {
		t.Fatalf("defaults check=%v timeout=%v minIdle=%d", check, timeout, minIdle)
	}
}

func TestAnyTLSPoolParamsHonorsYAML(t *testing.T) {
	o := &store.NodeOpts{
		IdleSessionCheckIntervalSec: 45,
		IdleSessionTimeoutSec:       90,
		MinIdleSession:              0,
		MinIdleSessionSet:           true,
		PaddingScheme:               "stop=3\n0=8-8\n1=40-40\n2=40-40\n",
		ClientMetadata:              "arc-test",
	}
	pad, meta, check, timeout, minIdle := anytlsPoolParams(o)
	if string(pad) != o.PaddingScheme || meta != "arc-test" {
		t.Fatal("pad/meta")
	}
	if check != 45*time.Second || timeout != 90*time.Second || minIdle != 0 {
		t.Fatalf("honored check=%v timeout=%v minIdle=%d", check, timeout, minIdle)
	}
}
