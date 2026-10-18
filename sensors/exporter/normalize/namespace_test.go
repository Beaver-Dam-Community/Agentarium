package normalize

import (
	"bytes"
	"strconv"
	"testing"
)

// The Tetragon PID namespace inode reaches the in-memory witness hook only,
// never the exported KernelEvent.
func TestExecPIDNamespaceIsWitnessOnly(t *testing.T) {
	raw := mutate(t, q0(t, "process_exec"), func(m map[string]any) {
		p := m["process_exec"].(map[string]any)["process"].(map[string]any)
		ns, _ := p["ns"].(map[string]any)
		if ns == nil {
			ns = map[string]any{}
			p["ns"] = ns
		}
		ns["pid"] = map[string]any{"inum": 4026532777}
	})
	n := normalizer(t, raw)
	var gotID string
	var gotNS uint32
	n.c.ExecNamespace = func(id string, inode uint32) { gotID, gotNS = id, inode }
	wire, event := buildEvent(t, n, raw)
	if gotID == "" || gotID != event["process_exec_id"] || gotNS != 4026532777 {
		t.Fatalf("namespace hook %q %d", gotID, gotNS)
	}
	if bytes.Contains(wire, []byte(strconv.Itoa(4026532777))) {
		t.Fatal("PID namespace exported")
	}
}
