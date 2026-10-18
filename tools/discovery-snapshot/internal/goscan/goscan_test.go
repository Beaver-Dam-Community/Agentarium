package goscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanFixtureModule(t *testing.T) {
	root, err := filepath.Abs("testdata/mod")
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	graph, cs, err := Scan(root, env)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if cs.Language != "go" || cs.Tool != "golang.org/x/tools/go/callgraph/vta" {
		t.Fatalf("unexpected header: %+v", cs)
	}

	type key struct{ caller, callee, cat string }
	got := map[key]string{}
	for _, s := range cs.CallSites {
		got[key{s.Caller, s.Callee, s.Category}] = s.Path
		if s.Line <= 0 || s.Column <= 0 {
			t.Errorf("site without position: %+v", s)
		}
	}
	want := []key{
		// Interface call resolved by VTA to the concrete *http.Client.
		{"example.com/scanfixture/client.Fetch", "(*net/http.Client).Do", "net/http"},
		{"example.com/scanfixture/client.Fetch", "net/http.NewRequest", "net/http"},
		{"example.com/scanfixture/client.Dial", "crypto/tls.Dial", "crypto/tls"},
		{"example.com/scanfixture/client.Resolve", "net.LookupHost", "net"},
		{"example.com/scanfixture/client.ReadConfig", "os.ReadFile", "os.open"},
		{"example.com/scanfixture/internal/run.Run", "os/exec.Command", "os/exec"},
	}
	for _, w := range want {
		p, ok := got[w]
		if !ok {
			t.Errorf("missing call site %+v", w)
			continue
		}
		if filepath.IsAbs(p) || p == "" {
			t.Errorf("path must be relative: %q", p)
		}
	}
	for k := range got {
		if k.callee == "os.Getenv" {
			t.Errorf("os.Getenv is not a file-open target")
		}
	}
	if _, ok := graph["example.com/scanfixture/client.Fetch"]; !ok {
		t.Errorf("callgraph lacks Fetch; keys=%v", len(graph))
	}
	for sym := range graph {
		if sym == "net/http.NewRequest" {
			t.Errorf("callgraph keys must be module functions only")
		}
	}
}
