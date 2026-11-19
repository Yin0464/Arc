package main

// wantNodes is the synthetic fixture's node count per tab
// (cmd/codegen/testdata/synthetic).
var wantNodes = map[string]int{
	"香港":  4,
	"日本":  1,
	"台湾":  1,
	"新加坡": 2,
	"其他":  4,
}
