package seed

import (
	"os"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/bootstrap"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/pki"
)

func TestSeedFile(t *testing.T) {
	data, err := os.ReadFile("../../seed/registered_workloads.yaml")
	if err != nil {
		t.Fatal(err)
	}
	regs, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]pki.Role{}
	for _, r := range regs {
		byKey[r.Namespace+"/"+r.KSA] = r.Role
	}
	// M1-2 scope: netpol-collector is registered (TASK-06 KSA table).
	want := map[string]pki.Role{
		"agent-sensors/netpol-collector":   pki.RoleService,
		"agent-control/workload-identity":  pki.RoleService,
		"agent-control/policy-gateway":     pki.RoleService,
		"agent-observe/control-health":     pki.RoleService,
		"agent-observe/audit-writer":       pki.RoleService,
		"agent-exec/agent-runtime":         pki.RoleRuntime,
		"agent-exec/probe-runner":          pki.RoleProbe,
		"agent-adapters/probe-runner":      pki.RoleProbe,
		"agent-adapters/model-adapter":     pki.RoleAdapter,
		"agent-adapters/kubernetes-reader": pki.RoleAdapter,
	}
	for k, role := range want {
		if byKey[k] != role {
			t.Errorf("%s: role %q, want %q", k, byKey[k], role)
		}
	}
	for _, r := range regs {
		if r.Namespace+"/"+r.KSA == "agent-adapters/model-adapter" && r.AdapterID != "model" {
			t.Errorf("model-adapter adapter_id = %q, want catalog value model", r.AdapterID)
		}
	}
}

// The lifecycle sources must be registered as services under their exact
// namespace/KSA, or bootstrap would not bind their certificates to the Pod.
func TestSeedLifecycleSourcesPodBound(t *testing.T) {
	data, err := os.ReadFile("../../seed/registered_workloads.yaml")
	if err != nil {
		t.Fatal(err)
	}
	regs, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range regs {
		if r.Role == pki.RoleService && bootstrap.PodBound(r.Role, r.Namespace, r.KSA) {
			if r.ServicePrincipal != r.KSA {
				t.Errorf("%s/%s: service_principal %q", r.Namespace, r.KSA, r.ServicePrincipal)
			}
			got[r.Namespace+"/"+r.KSA] = true
		}
	}
	if len(got) != 2 || !got["agent-sensors/lifecycle-recorder"] || !got["agent-observe/pod-watcher"] {
		t.Fatalf("pod-bound services in seed = %v", got)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":             "workloads:\n  - {namespace: a, ksa: b, role: service, service_principal: b, extra: 1}\n",
		"unknown role":              "workloads:\n  - {namespace: a, ksa: b, role: admin}\n",
		"node bridge":               "workloads:\n  - {namespace: a, ksa: b, role: node_bridge}\n",
		"duplicate":                 "workloads:\n  - {namespace: a, ksa: b, role: runtime}\n  - {namespace: a, ksa: b, role: runtime}\n",
		"adapter without id":        "workloads:\n  - {namespace: a, ksa: b, role: adapter}\n",
		"id on non-adapter":         "workloads:\n  - {namespace: a, ksa: b, role: runtime, adapter_id: x}\n",
		"service without principal": "workloads:\n  - {namespace: a, ksa: b, role: service}\n",
		"bad label":                 "workloads:\n  - {namespace: A, ksa: b, role: runtime}\n",
		"two documents":             "workloads:\n  - {namespace: a, ksa: b, role: runtime}\n---\nworkloads: []\n",
		"empty":                     "workloads: []\n",
	}
	for name, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%s: empty error", name)
		}
	}
}
