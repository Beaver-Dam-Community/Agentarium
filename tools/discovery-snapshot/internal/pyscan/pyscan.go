// Package pyscan runs the Python ast scanner (pyscan/scan.py) and decodes its
// output into the snapshot format.
package pyscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/format"
)

type output struct {
	Callgraph format.Callgraph `json:"callgraph"`
	CallSites format.CallSites `json:"call_sites"`
}

// Scan writes script to a temp file and runs `python <script> <root>`.
func Scan(ctx context.Context, python string, script []byte, root string) (format.Callgraph, format.CallSites, error) {
	dir, err := os.MkdirTemp("", "pyscan-")
	if err != nil {
		return nil, format.CallSites{}, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "scan.py")
	if err := os.WriteFile(path, script, 0o600); err != nil {
		return nil, format.CallSites{}, err
	}
	// -I: isolated mode, so nothing from the scanned tree or cwd is imported.
	cmd := exec.CommandContext(ctx, python, "-I", path, root)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, format.CallSites{}, fmt.Errorf("python scanner: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var o output
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return nil, format.CallSites{}, fmt.Errorf("python scanner output: %w", err)
	}
	if o.CallSites.Language != format.LanguagePython {
		return nil, format.CallSites{}, fmt.Errorf("python scanner returned language %q", o.CallSites.Language)
	}
	if o.Callgraph == nil {
		o.Callgraph = format.Callgraph{}
	}
	return o.Callgraph, o.CallSites, nil
}
