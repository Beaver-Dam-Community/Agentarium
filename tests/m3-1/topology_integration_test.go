//go:build integration

package m31

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// The fixed Kubernetes stand-in: one node with one boot and one "pod" per
// workload. The identity harness answers TokenReview/Pod/Node from exactly
// this table (harnessCluster), and control-health's harness answers the
// node's current boot from it (harnessNodes).

const (
	environment = "test"      // catalog/gcp target environment
	tenant      = "hackathon" // catalog/gcp target tenant
	nodeName    = "m31-node-a"
	sanPrefix   = "spiffe://agentarium.internal/ns/"
)

type pod struct {
	Namespace string `json:"namespace"`
	KSA       string `json:"ksa"`
	PodName   string `json:"pod_name"`
	PodUID    string `json:"pod_uid"`
	NodeName  string `json:"node_name"`
	token     string
}

func (p pod) san() string { return sanPrefix + p.Namespace + "/sa/" + p.KSA }

type topology struct {
	NodeUID, BootID, ClusterUID string
	pods                        map[string]pod // by short name
}

// workloads are the M3-1 action path services plus the simulated node-side
// components, by short name.
var workloads = map[string][2]string{
	"credential-broker":  {"agent-control", "credential-broker"},
	"gateway":            {"agent-control", "policy-gateway"},
	"coordinator":        {"agent-control", "coordinator"},
	"receiver-sender":    {"agent-adapters", "receiver-sender"},
	"receiver":           {"agent-targets", "receiver"},
	"evidence-collector": {"agent-observe", "evidence-collector"},
	"control-health":     {"agent-observe", "control-health"},
	"audit-writer":       {"agent-observe", "audit-writer"},
	"audit-exporter":     {"agent-observe", "audit-exporter"},
	// Simulated node-side components (README "Simulated locally").
	"tetragon":           {"agent-sensors", "tetragon"},
	"lifecycle-recorder": {"agent-sensors", "lifecycle-recorder"},
	"node-readiness":     {"agent-control", "node-readiness"},
	// Runtime pods, one per agent session run.
	"runtime-1": {"agent-exec", "agent-runtime"},
	"runtime-2": {"agent-exec", "agent-runtime"},
}

func newTopology(t *testing.T, e env) topology {
	t.Helper()
	top := topology{NodeUID: uuid.NewString(), BootID: uuid.NewString(), ClusterUID: uuid.NewString(), pods: map[string]pod{}}
	for name, w := range workloads {
		p := pod{Namespace: w[0], KSA: w[1], PodName: name + "-0", PodUID: uuid.NewString(), NodeName: nodeName, token: "m31-" + randomHex(24)}
		if err := os.MkdirAll(filepath.Dir(top.tokenFile(e, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		// 0644: the runtime container reads it as a non-root uid.
		writeFile(t, top.tokenFile(e, name), []byte(p.token), 0o644)
		top.pods[name] = p
	}
	return top
}

func (top topology) tokenFile(e env, name string) string { return e.path("tokens", name, "token") }

// tokenTable is the identity harness "tokens" map: token -> pod.
func (top topology) tokenTable() map[string]pod {
	out := map[string]pod{}
	for _, p := range top.pods {
		out[p.token] = p
	}
	return out
}

func (top topology) runtimeSAN(name string) string {
	p := top.pods[name]
	return p.san() + "/pod/" + p.PodUID
}
