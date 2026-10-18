// Package goscan builds a VTA call graph for a Go module and lists call sites
// into net, net/http, crypto/tls, os/exec and the os file-open functions.
package goscan

import (
	"fmt"
	"go/token"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/format"
)

// TargetPackages are the packages whose functions count as call-site targets
// (TASK-02 3.4).
var TargetPackages = map[string]bool{
	"net":        true,
	"net/http":   true,
	"crypto/tls": true,
	"os/exec":    true,
}

// osOpenFuncs are the os functions that open files.
var osOpenFuncs = map[string]bool{
	"Open": true, "OpenFile": true, "Create": true, "ReadFile": true, "WriteFile": true,
}

var limitations = []string{
	"VTA resolves calls only through values visible in the loaded module and its dependencies; reflection, plugin loading and cgo are not followed",
	"call sites are listed only for functions defined in the scanned module",
}

// Category returns the call-site category for callee, or "" if it is not a target.
func Category(fn *ssa.Function) string {
	pkg := fn.Pkg
	if pkg == nil && fn.Origin() != nil {
		pkg = fn.Origin().Pkg
	}
	if pkg == nil {
		return ""
	}
	path := pkg.Pkg.Path()
	if TargetPackages[path] {
		return path
	}
	if path == "os" && fn.Signature.Recv() == nil && osOpenFuncs[fn.Name()] {
		return "os.open"
	}
	return ""
}

// Scan loads every package under root ("./...") and returns the call graph
// (symbol -> callees, for functions of the scanned module) and call sites.
func Scan(root string, env []string) (format.Callgraph, format.CallSites, error) {
	cfg := &packages.Config{
		Mode:  packages.LoadAllSyntax | packages.NeedModule,
		Dir:   root,
		Tests: false,
		Env:   env,
	}
	initial, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, format.CallSites{}, fmt.Errorf("load packages: %w", err)
	}
	if n := packages.PrintErrors(initial); n > 0 {
		return nil, format.CallSites{}, fmt.Errorf("load packages: %d errors", n)
	}
	if len(initial) == 0 {
		return nil, format.CallSites{}, fmt.Errorf("no Go packages under %s", root)
	}
	if err := checkContained(root, initial); err != nil {
		return nil, format.CallSites{}, err
	}
	own := map[string]bool{}
	for _, p := range initial {
		own[p.PkgPath] = true
	}

	prog, _ := ssautil.AllPackages(initial, ssa.InstantiateGenerics)
	prog.Build()
	cg := vta.CallGraph(ssautil.AllFunctions(prog), cha.CallGraph(prog))
	cg.DeleteSyntheticNodes()

	graph := format.Callgraph{}
	var sites []format.CallSite
	seen := map[string]bool{}
	for fn, node := range cg.Nodes {
		if fn == nil || !isOwn(fn, own) {
			continue
		}
		caller := fn.String()
		callees := map[string]bool{}
		for _, e := range node.Out {
			callee := e.Callee.Func
			callees[callee.String()] = true
			cat := Category(callee)
			if cat == "" || e.Site == nil {
				continue
			}
			pos := prog.Fset.Position(e.Site.Pos())
			// Package init edges have no source position.
			if !pos.IsValid() {
				continue
			}
			site := format.CallSite{
				Caller:   caller,
				Callee:   callee.String(),
				Category: cat,
				Path:     relPath(root, pos),
				Line:     pos.Line,
				Column:   pos.Column,
			}
			key := fmt.Sprintf("%s|%s|%s|%d|%d", site.Caller, site.Callee, site.Path, site.Line, site.Column)
			if !seen[key] {
				seen[key] = true
				sites = append(sites, site)
			}
		}
		list := make([]string, 0, len(callees))
		for c := range callees {
			list = append(list, c)
		}
		sort.Strings(list)
		graph[caller] = list
	}
	sortSites(sites)
	if sites == nil {
		sites = []format.CallSite{}
	}
	return graph, format.CallSites{
		Language:    format.LanguageGo,
		Tool:        "golang.org/x/tools/go/callgraph/vta",
		CallSites:   sites,
		Imports:     []format.ImportAlias{},
		Limitations: limitations,
	}, nil
}

// checkContained refuses packages of a directory replacement (`replace m =>
// ./dir` or an absolute path) loaded from outside root: that code is not part
// of the fetched, digest-checked source. Vendored copies load from root/vendor.
func checkContained(root string, initial []*packages.Package) error {
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	var bad error
	packages.Visit(initial, nil, func(p *packages.Package) {
		m := p.Module
		if bad != nil || m == nil || m.Replace == nil || m.Replace.Version != "" {
			return
		}
		dir, err := filepath.EvalSymlinks(p.Dir)
		rel, relErr := filepath.Rel(base, dir)
		if err != nil || relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			bad = fmt.Errorf("package %s: replacement %q is outside the source root", p.PkgPath, m.Replace.Path)
		}
	})
	return bad
}

func isOwn(fn *ssa.Function, own map[string]bool) bool {
	pkg := fn.Pkg
	if pkg == nil && fn.Origin() != nil {
		pkg = fn.Origin().Pkg
	}
	return pkg != nil && own[pkg.Pkg.Path()]
}

func relPath(root string, pos token.Position) string {
	if pos.Filename == "" {
		return ""
	}
	rel, err := filepath.Rel(root, pos.Filename)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(pos.Filename)
	}
	return filepath.ToSlash(rel)
}

func sortSites(s []format.CallSite) {
	sort.Slice(s, func(i, j int) bool {
		a, b := s[i], s[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.Callee < b.Callee
	})
}
