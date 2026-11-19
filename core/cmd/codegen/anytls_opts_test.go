package main

import "testing"

func TestIntOrDurationSec(t *testing.T) {
	m := map[string]any{
		"idle-session-timeout":        60,
		"idle-session-check-interval": "30s",
		"min-idle-session":            "0",
	}
	if v, ok := intOrDurationSec(m, "idle-session-timeout"); !ok || v != 60 {
		t.Fatalf("timeout %v %v", v, ok)
	}
	if v, ok := intOrDurationSec(m, "idle-session-check-interval"); !ok || v != 30 {
		t.Fatalf("check %v %v", v, ok)
	}
	if v, ok := intOrDurationSec(m, "min-idle-session"); !ok || v != 0 {
		t.Fatalf("minIdle %v %v", v, ok)
	}
	if _, ok := intOrDurationSec(m, "missing"); ok {
		t.Fatal("missing should be unset")
	}
}

func TestNodeOptsFromIdleFields(t *testing.T) {
	o := nodeOptsFrom(map[string]any{
		"client-fingerprint":          "chrome",
		"udp":                         true,
		"idle-session-check-interval": 40,
		"idle-session-timeout":        "90s",
		"min-idle-session":            0,
		"padding-scheme":              "stop=3\n0=8-8\n",
		"client-metadata":             "meta",
	}, "n", "padding-scheme", "client-metadata")
	if o.idleCheck != 40 || o.idleTO != 90 || !o.minIdleSet || o.minIdle != 0 {
		t.Fatalf("idle fields %+v", o)
	}
	if o.padding == "" || o.metadata != "meta" || o.fp != "chrome" || !o.udp {
		t.Fatalf("other fields %+v", o)
	}
	blank := nodeOptsFrom(map[string]any{"type": "anytls", "padding-scheme": "x"}, "n", "", "")
	if blank.idleCheck != 0 || blank.idleTO != 0 || blank.minIdleSet || blank.padding != "" || blank.metadata != "" {
		t.Fatalf("blank should keep Arc defaults unset %+v", blank)
	}
}

func TestNodeOptsFromRejectsInvalidSessionOpts(t *testing.T) {
	// Small positive values are kept as configured, not replaced.
	o := nodeOptsFrom(map[string]any{"idle-session-timeout": 3, "idle-session-check-interval": "2s"}, "n", "", "")
	if o.idleTO != 3 || o.idleCheck != 2 {
		t.Fatalf("small values not kept %+v", o)
	}
	for name, m := range map[string]map[string]any{
		"timeout-zero":     {"idle-session-timeout": 0},
		"timeout-negative": {"idle-session-timeout": -5},
		"timeout-garbage":  {"idle-session-timeout": "soon"},
		"check-zero":       {"idle-session-check-interval": "0s"},
		"check-negative":   {"idle-session-check-interval": "-30s"},
		"min-negative":     {"min-idle-session": -1},
		"min-garbage":      {"min-idle-session": "two"},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: accepted", name)
				}
			}()
			nodeOptsFrom(m, name, "", "")
		}()
	}
}

func TestRequirePlainTransportRejectsUnsupported(t *testing.T) {
	requirePlainTransport(map[string]any{"network": "tcp", "client-fingerprint": "chrome"}, "ok")
	requirePlainTransport(map[string]any{}, "ok")
	for name, m := range map[string]map[string]any{
		"ws":          {"network": "ws"},
		"grpc":        {"network": "grpc"},
		"reality":     {"reality-opts": map[string]any{"public-key": "k"}},
		"ech":         {"ech-opts": map[string]any{"enable": true}},
		"pin":         {"fingerprint": "aa:bb"},
		"certificate": {"certificate": "CERT"},
		"ss-opts":     {"ss-opts": map[string]any{"enabled": true, "method": "aes-128-gcm", "password": "p"}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: accepted", name)
				}
			}()
			requirePlainTransport(m, name)
		}()
	}
}
