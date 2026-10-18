package main

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func matrix(t *testing.T) Matrix {
	t.Helper()
	var m Matrix
	if err := decode("../../deploy/gcp/base/network/allow-matrix.yaml", &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func TestDeterministicAndCommitted(t *testing.T) {
	m := matrix(t)
	got, err := render(m)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../deploy/gcp/base/network/rendered/policies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(got, '\n'), want) {
		t.Fatal("regenerate committed NetworkPolicies")
	}
	for i, j := 0, len(m.Edges)-1; i < j; i, j = i+1, j-1 {
		m.Edges[i], m.Edges[j] = m.Edges[j], m.Edges[i]
	}
	again, err := render(m)
	if err != nil || !bytes.Equal(got, again) {
		t.Fatal("input order changed policy")
	}
}
func TestExecutionInfraRejected(t *testing.T) {
	m := matrix(t)
	m.InfraEdges = append(m.InfraEdges, InfraEdge{From: "agent-exec/agent-runtime", To: []string{"metadata"}})
	if _, err := render(m); err == nil {
		t.Fatal("execution metadata bypass accepted")
	}
}
func TestUnsafeMatrixRejected(t *testing.T) {
	for _, kind := range []string{"unknown_caller", "unknown_callee", "wildcard_ip", "bad_port", "empty_dns_selector"} {
		t.Run(kind, func(t *testing.T) {
			m := matrix(t)
			switch kind {
			case "unknown_caller":
				m.Edges[0].From = "agent-control/unknown"
			case "unknown_callee":
				m.Edges[0].To = "agent-control/unknown"
			case "wildcard_ip":
				m.Infra["cloudsql"] = Infra{IPBlock: "0.0.0.0/0", Ports: []string{"TCP/3307"}}
			case "bad_port":
				m.Edges[0].Port = "TCP/0"
			case "empty_dns_selector":
				m.Infra["kube_dns"] = Infra{Namespace: "kube-system", Ports: []string{"UDP/53"}}
			}
			if _, err := render(m); err == nil {
				t.Fatal("accepted unsafe matrix")
			}
		})
	}
}

// Match examples semantically because the spec groups peers with In selectors
// while the renderer emits one namespace+KSA peer per rule. Both must describe
// exactly the same L3/L4 permission set; byte-for-byte grouping is irrelevant.
func TestTask06Examples(t *testing.T) {
	raw, err := os.ReadFile("../../docs/tech-specs/TASK-06-egress-credentials.md")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(raw), "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy")
	if start < 0 {
		t.Fatal("example missing")
	}
	block := strings.SplitN(string(raw)[start:], "```", 2)[0]
	decoder := yaml.NewDecoder(strings.NewReader(block))
	examples := []policy{}
	for {
		var v map[string]any
		if err := decoder.Decode(&v); err != nil {
			break
		}
		b, _ := json.Marshal(v)
		var p policy
		_ = json.Unmarshal(b, &p)
		examples = append(examples, p)
	}
	got, err := render(matrix(t))
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Items []policy `json:"items"`
	}
	_ = json.Unmarshal(got, &list)
	for _, example := range examples {
		var actual *policy
		for i := range list.Items {
			p := &list.Items[i]
			if reflect.DeepEqual(p.Metadata["name"], example.Metadata["name"]) && reflect.DeepEqual(p.Metadata["namespace"], example.Metadata["namespace"]) {
				actual = p
				break
			}
		}
		if actual == nil {
			t.Fatalf("missing %v", example.Metadata)
		}
		for _, direction := range []string{"ingress", "egress"} {
			want := permissions(t, example.Spec[direction], direction)
			got := permissions(t, actual.Spec[direction], direction)
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("%s/%s %s permissions differ\nwant %v\ngot %v", example.Metadata["namespace"], example.Metadata["name"], direction, want, got)
			}
		}
	}
}
func permissions(t *testing.T, value any, direction string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	if value == nil {
		return out
	}
	rules := value.([]any)
	peerKey := "to"
	if direction == "ingress" {
		peerKey = "from"
	}
	for _, r := range rules {
		rule := r.(map[string]any)
		ports, _ := json.Marshal(rule["ports"])
		for _, p := range rule[peerKey].([]any) {
			peer := p.(map[string]any)
			if ip, ok := peer["ipBlock"]; ok {
				b, _ := json.Marshal(ip)
				out[string(b)+string(ports)] = true
				continue
			}
			ns := peer["namespaceSelector"].(map[string]any)["matchLabels"].(map[string]any)["kubernetes.io/metadata.name"].(string)
			selector := peer["podSelector"].(map[string]any)
			if labels, ok := selector["matchLabels"]; ok {
				b, _ := json.Marshal(labels)
				out[ns+string(b)+string(ports)] = true
			} else {
				for _, e := range selector["matchExpressions"].([]any) {
					ex := e.(map[string]any)
					if ex["operator"] != "In" {
						t.Fatal("unexpected selector")
					}
					for _, v := range ex["values"].([]any) {
						b, _ := json.Marshal(map[string]any{ex["key"].(string): v})
						out[ns+string(b)+string(ports)] = true
					}
				}
			}
		}
	}
	return out
}

func TestCommonCallerCoverage(t *testing.T) {
	var mapping struct {
		Version         int               `yaml:"version"`
		DeferredCallers map[string]string `yaml:"deferred_callers"`
		APIs            []struct {
			API    string `yaml:"api"`
			Caller string `yaml:"caller"`
			Routes []Edge `yaml:"routes"`
		} `yaml:"apis"`
	}
	if err := decode("../../deploy/gcp/base/network/caller-map.yaml", &mapping); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../docs/tech-specs/COMMON.md")
	if err != nil {
		t.Fatal(err)
	}
	section := strings.SplitN(strings.SplitN(string(raw), "## Internal API responsibilities", 2)[1], `<a id="api-implementation-contract-ref"></a>`, 2)[0]
	documented := map[string]string{}
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "| `") {
			cols := strings.Split(line, "|")
			documented[strings.TrimSpace(cols[1])] = strings.TrimSpace(cols[3])
		}
	}
	m := matrix(t)
	edges := map[Edge]bool{}
	for _, e := range m.Edges {
		edges[e] = true
	}
	seen := map[string]bool{}
	for _, entry := range mapping.APIs {
		caller, ok := documented[entry.API]
		if !ok || caller != entry.Caller || seen[entry.API] {
			t.Fatalf("unknown/changed/duplicate API caller mapping: %s", entry.API)
		}
		seen[entry.API] = true
		if len(entry.Routes) == 0 {
			t.Fatalf("no explicit route mapping: %s", entry.API)
		}
		for _, e := range entry.Routes {
			if !edges[e] {
				t.Errorf("missing caller/API route %s: %+v", entry.API, e)
			}
		}
	}
	for api := range documented {
		if !seen[api] {
			t.Errorf("unmapped COMMON API: %s", api)
		}
	}
}
