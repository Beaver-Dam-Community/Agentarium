package egress

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// peerSet flattens rendered rules to "<peer>|<ports>" strings. A pod peer is
// "<namespace>/<label value>", an address peer its CIDR.
func peerSet(t *testing.T, rules []rule, egress bool) []string {
	t.Helper()
	var out []string
	for _, r := range rules {
		var ports []string
		for _, p := range r.Ports {
			ports = append(ports, p.Protocol+"/"+itoa(p.Port))
		}
		sort.Strings(ports)
		peers := r.From
		if egress {
			peers = r.To
		}
		for _, p := range peers {
			name := p.IPBlock["cidr"]
			if name == "" {
				ns, _ := p.NamespaceSelector["matchLabels"].(map[string]any)["kubernetes.io/metadata.name"].(string)
				labels, _ := p.PodSelector["matchLabels"].(map[string]any)
				var values []string
				for _, v := range labels {
					values = append(values, v.(string))
				}
				if exprs, ok := p.PodSelector["matchExpressions"].([]any); ok {
					for _, e := range exprs {
						for _, v := range e.(map[string]any)["values"].([]any) {
							values = append(values, v.(string))
						}
					}
				}
				sort.Strings(values)
				name = ns + "/" + strings.Join(values, ",")
			}
			out = append(out, name+"|"+strings.Join(ports, ","))
		}
	}
	sort.Strings(out)
	return out
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// TestAuditExportPaths pins the TASK-07 3.2.1 (#163) paths: the verifier
// reaches audit-writer (export_verification_failed) and control-health
// (audit_integrity hold), the exporter reaches control-health (export_lag
// hold, probe-results, release), the retention job reaches only Cloud SQL
// infrastructure, and none of them accepts ingress.
func TestAuditExportPaths(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/gcp/base/network/rendered/policies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Items []policy }
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	infra := []string{
		"${cloudsql_private_ip}/32|TCP/3307", "169.254.169.254/32|TCP/80,TCP/8080",
		"199.36.153.8/30|TCP/443", "kube-system/kube-dns|TCP/53,UDP/53",
	}
	with := func(extra ...string) []string {
		out := append(append([]string(nil), infra...), extra...)
		sort.Strings(out)
		return out
	}
	want := map[string][]string{
		"audit-exporter":  with("agent-control/workload-identity|TCP/8443", "agent-observe/control-health|TCP/8443"),
		"audit-verifier":  with("agent-control/workload-identity|TCP/8443", "agent-observe/audit-writer|TCP/8443", "agent-observe/control-health|TCP/8443"),
		"audit-retention": with(),
	}
	found := map[string]bool{}
	for _, p := range list.Items {
		ksa := strings.TrimSuffix(p.Metadata.Name, "-allow")
		if p.Metadata.Namespace == "agent-observe" && ksa == "audit-writer" {
			if !contains(peerSet(t, p.Spec.Ingress, false), "agent-observe/", "audit-verifier") {
				t.Fatal("audit-writer ingress must admit audit-verifier")
			}
		}
		expected, ok := want[ksa]
		if p.Metadata.Namespace != "agent-observe" || !ok {
			continue
		}
		found[ksa] = true
		if got := peerSet(t, p.Spec.Egress, true); !reflect.DeepEqual(got, expected) {
			t.Errorf("%s egress\n got %v\nwant %v", ksa, got, expected)
		}
		if len(p.Spec.Ingress) != 0 {
			t.Errorf("%s must not accept ingress: %+v", ksa, p.Spec.Ingress)
		}
	}
	if len(found) != len(want) {
		t.Fatalf("missing rendered policies: %v", found)
	}
}

func contains(peers []string, namespace, ksa string) bool {
	for _, p := range peers {
		peer, _, _ := strings.Cut(p, "|")
		if ns, labels, ok := strings.Cut(peer, "/"); ok && ns+"/" == namespace {
			for _, l := range strings.Split(labels, ",") {
				if l == ksa {
					return true
				}
			}
		}
	}
	return false
}
