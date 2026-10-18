// Package egress checks rendered policy boundaries without claiming dataplane
// enforcement. Live GKE allow/deny probes remain a separate deployment gate.
package egress

import (
	"encoding/json"
	"os"
	"testing"
)

type policy struct {
	Metadata struct {
		Name, Namespace string
		Annotations     map[string]string
	}
	Spec struct {
		PodSelector map[string]any
		PolicyTypes []string
		Ingress     []rule
		Egress      []rule
	}
}
type rule struct {
	From, To []peer
	Ports    []struct {
		Protocol string
		Port     int
	}
}
type peer struct {
	NamespaceSelector, PodSelector map[string]any
	IPBlock                        map[string]string
}

func TestExecutionBoundary(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/gcp/base/network/rendered/policies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Items []policy }
	if json.Unmarshal(raw, &list) != nil {
		t.Fatal("invalid rendered policies")
	}
	found := map[string]bool{}
	for _, p := range list.Items {
		if p.Metadata.Namespace != "agent-exec" {
			continue
		}
		found[p.Metadata.Name] = true
		if len(p.Spec.Ingress) != 0 {
			t.Fatalf("execution ingress opened by %s", p.Metadata.Name)
		}
		if p.Metadata.Name == "default-deny" {
			if len(p.Spec.Egress) != 0 || len(p.Spec.PodSelector) != 0 {
				t.Fatal("default deny is not blanket")
			}
			continue
		}
		for _, r := range p.Spec.Egress {
			if len(r.Ports) != 1 || r.Ports[0].Protocol != "TCP" || r.Ports[0].Port != 8443 {
				t.Fatal("execution permits non-8443 egress")
			}
			for _, peer := range r.To {
				if peer.IPBlock != nil || peer.NamespaceSelector == nil || peer.PodSelector == nil {
					t.Fatal("execution has unscoped/IP egress")
				}
				ns := peer.NamespaceSelector["matchLabels"].(map[string]any)["kubernetes.io/metadata.name"]
				ksa := peer.PodSelector["matchLabels"].(map[string]any)["app.kubernetes.io/name"]
				allowed := ns == "agent-control" && ksa == "policy-gateway"
				if p.Metadata.Name == "probe-runner-allow" {
					allowed = allowed || ns == "agent-targets" && ksa == "probe-sink"
				}
				if p.Metadata.Name == "start-fixture-allow" {
					allowed = allowed || ns == "agent-targets" && ksa == "start-marker"
				}
				if !allowed {
					t.Fatalf("unapproved direct execution peer %v %v", ns, ksa)
				}
			}
		}
	}
	for _, name := range []string{"default-deny", "agent-runtime-allow", "probe-runner-allow", "start-fixture-allow"} {
		if !found[name] {
			t.Fatalf("missing execution policy %s", name)
		}
	}
}
func TestPodPeersRequireNamespaceAndLabel(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/gcp/base/network/rendered/policies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Items []policy }
	if json.Unmarshal(raw, &list) != nil {
		t.Fatal("invalid policies")
	}
	for _, p := range list.Items {
		for _, r := range append(p.Spec.Ingress, p.Spec.Egress...) {
			for _, peer := range append(r.From, r.To...) {
				if peer.IPBlock != nil {
					continue
				}
				if peer.NamespaceSelector == nil || peer.PodSelector == nil || len(peer.PodSelector) == 0 || len(peer.NamespaceSelector) == 0 {
					t.Fatalf("OR/broad selector in %s/%s", p.Metadata.Namespace, p.Metadata.Name)
				}
			}
		}
	}
}

func TestAllowLoggingScope(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/gcp/base/network/rendered/policies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Items []policy }
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	for _, p := range list.Items {
		want := p.Metadata.Name != "default-deny" && (p.Metadata.Namespace == "agent-exec" || p.Metadata.Namespace == "agent-adapters")
		if (p.Metadata.Annotations["policy.network.gke.io/enable-logging"] == "true") != want {
			t.Fatalf("wrong allow logging scope: %s/%s", p.Metadata.Namespace, p.Metadata.Name)
		}
	}
}
