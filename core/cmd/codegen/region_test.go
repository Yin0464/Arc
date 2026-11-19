package main

import "testing"

var testAliases = map[string]string{"星洲": "新加坡", "台灣": "台湾", "美國": "美国"}

func TestRegionOfPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"香港 01":   "香港",
		"香港01":    "香港",
		"星洲 3":    "新加坡",
		"台灣 2":    "台湾",
		"韩国 1":    "韩国",
		"德国 法兰克福": "德国",
		"美國 1":    "美国",
		"其他地区 1":  "其他地区",
	} {
		if got := regionOf(in, testAliases); got != want {
			t.Errorf("regionOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSkippedMainRegionPanics(t *testing.T) {
	for _, name := range []string{"中转香港 01", "经星洲 2"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%q: a name mentioning a main region outside it must panic", name)
				}
			}()
			mustNotMentionMain(name, "src", testAliases)
		}()
	}
}

func TestSkippedOtherRegionOK(t *testing.T) {
	mustNotMentionMain("韩国 01", "src", testAliases)
}

func TestSamePasswordEmptyPanicsClearly(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("empty list must panic")
		}
	}()
	samePassword(nil, "src")
}

func TestCleanName(t *testing.T) {
	src := &Source{CleanFromFirstHan: true, CleanCutAt: " ("}
	for in, want := range map[string]string{
		"x1 香港 01 (tag)": "香港 01",
		"日本 2":           "日本 2",
		"no-han (a)":     "no-han",
	} {
		if got := cleanName(in, src); got != want {
			t.Errorf("cleanName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cleanName("  raw  ", &Source{}); got != "  raw  " {
		t.Errorf("no rules must keep the name, got %q", got)
	}
}

func TestNodeName(t *testing.T) {
	if got := nodeName("{country} {n:02}", "日本", 3); got != "日本 03" {
		t.Fatal(got)
	}
	if got := nodeName("{country}住宅 {n}", "日本", 12); got != "日本住宅 12" {
		t.Fatal(got)
	}
}

func TestTypeAccepted(t *testing.T) {
	if !typeAccepted(" Trojan ", []string{"trojan"}) || typeAccepted("vmess", []string{"trojan"}) {
		t.Fatal("type match")
	}
}
