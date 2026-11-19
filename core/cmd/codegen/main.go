package main

import (
	"arc/core/internal/store"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// rawDir holds the rule-library sources. build.sh fetches them fresh into a
// temp dir (tools/fetch_rules.py); codegen itself never downloads.
var rawDir string

// fixture is set by -fixture: tables from the committed excerpt below, which
// is far smaller than any real upstream list, so the size floors are relaxed.
var fixture bool

const (
	fixtureRules = "cmd/codegen/testdata/rules"
	routerDir    = "internal/router"
)

const usage = `usage: codegen RULES_DIR INPUT_JSON NODES_OUT
       codegen -fixture
  RULES_DIR   rule-library sources (tools/fetch_rules.py output)
  INPUT_JSON  source rules from the private bundle (tools/private.py emit)
  NODES_OUT   node table to write; must be outside this repository
  -fixture    write only the routing tables, from the committed test excerpt
              ` + fixtureRules + ` (offline tests on a fresh clone)
Run from core/. Routing tables are written to ` + routerDir + `/{dom,ip4,ip6}.bin.`

func main() {
	if _, err := os.Stat(filepath.Join(routerDir, "cndata.go")); err != nil {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if len(os.Args) == 2 && os.Args[1] == "-fixture" {
		fixture, rawDir = true, fixtureRules
		writeCNData(routerDir)
		fmt.Println("✅ 测试用路由表 dom/ip4/ip6.bin 生成完成（夹具，不能用于打包）")
		return
	}
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	rawDir = os.Args[1]
	nodesOut, err := filepath.Abs(os.Args[3])
	check(err)
	repo, err := filepath.Abs("..")
	check(err)
	if rel, err := filepath.Rel(repo, nodesOut); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		panic("NODES_OUT must be outside the repository: the node table is private")
	}
	cat, summary := genNodes(readInput(os.Args[2]))
	b, err := cat.Encode()
	check(err)
	_, err = store.Parse(b)
	check(err)
	writePrivate(nodesOut, b)
	fmt.Println(summary)
	writeCNData(routerDir)
	fmt.Println("✅ 节点表与路由表 dom/ip4/ip6.bin 生成完成")
}

// writePrivate writes the node table 0600 via a temp file and rename.
func writePrivate(path string, b []byte) {
	check(os.MkdirAll(filepath.Dir(path), 0o700))
	f, err := os.CreateTemp(filepath.Dir(path), ".nodes-*.tmp")
	check(err)
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o600)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		_ = os.Remove(f.Name())
		panic(err)
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

// readLines reads one rule-library file. codegen never downloads: a missing
// file is a build error (tools/fetch_rules.py is the only fetcher).
func readLines(path string) []string {
	data, err := os.ReadFile(path)
	check(err)
	return strings.Split(string(data), "\n")
}

// floor fails the build when a list is shorter than any real upstream copy
// could be, so a truncated download never ships. The fixture only has to be
// non-empty.
func floor(n, min int, what string) {
	if n < min && (!fixture || n == 0) {
		panic(fmt.Sprintf("%s missing or truncated: %d < %d", what, n, min))
	}
}
