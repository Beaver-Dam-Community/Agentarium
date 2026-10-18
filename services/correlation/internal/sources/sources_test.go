package sources

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/netpol"
)

func repo(t *testing.T, rel string) []byte {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The repository allow matrix and lock example are the real inputs; only the
// network values are added here. kube-dns is the services range's .10.
func inputs(t *testing.T) Inputs {
	var lock map[string]any
	if err := json.Unmarshal(repo(t, "deploy/gcp/environment.lock.example.json"), &lock); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(lock)
	return Inputs{Lock: raw, Values: []byte(`{"control_plane_endpoint":"172.16.0.2","cloudsql_private_ip":"10.40.0.3","node_cidr":"10.10.0.0/20"}`),
		AllowMatrix: repo(t, "deploy/gcp/base/network/allow-matrix.yaml")}
}

func TestBuildAndDecide(t *testing.T) {
	table, env, err := Build(inputs(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := netpol.NewClassifier(env); err != nil {
		t.Fatalf("classifier from installation inputs: %v", err)
	}
	ip := netip.MustParseAddr
	cases := []struct {
		workload string
		dest     string
		port     int
		want     Verdict
	}{
		{"agent-exec/agent-runtime", "10.30.0.20", 8443, Allowed},           // gateway ClusterIP
		{"agent-exec/agent-runtime", "10.30.0.20", 9000, Unregistered},      // wrong port
		{"agent-exec/agent-runtime", "169.254.169.254", 80, Unregistered},   // metadata without edge
		{"agent-exec/agent-runtime", "203.0.113.9", 443, Unregistered},      // direct external
		{"agent-exec/agent-runtime", "10.30.0.10", 53, Unregistered},        // exec has no DNS edge
		{"agent-exec/agent-runtime", "10.20.1.5", 8443, Unknown},            // a Pod address
		{"agent-adapters/receiver-sender", "199.36.153.9", 443, Allowed},    // PGA edge
		{"agent-adapters/receiver-sender", "10.40.0.3", 3307, Allowed},      // Cloud SQL edge
		{"agent-adapters/receiver-sender", "10.30.0.10", 53, Allowed},       // kube-dns edge
		{"agent-adapters/receiver-sender", "172.16.0.2", 443, Unregistered}, // apiserver without edge
		{"agent-adapters/kubernetes-reader", "172.16.0.2", 443, Allowed},
	}
	for _, c := range cases {
		if got := table.Decide(c.workload, ip(c.dest), c.port); got != c.want {
			t.Errorf("%s -> %s:%d = %d, want %d", c.workload, c.dest, c.port, got, c.want)
		}
	}
	unknown := "agent-exec/agent-runtime"
	if !table.NetpolAllowed(&unknown, ip("10.20.1.5"), 8443) || table.NetpolAllowed(nil, ip("10.30.0.20"), 8443) || table.RiskAllowed(unknown, ip("203.0.113.9"), 443) {
		t.Fatal("adapter verdicts")
	}
}

func TestBuildFailsClosed(t *testing.T) {
	in := inputs(t)
	var lock map[string]any
	_ = json.Unmarshal(in.Lock, &lock)
	delete(lock["network"].(map[string]any), "gateway_cluster_ip")
	in.Lock, _ = json.Marshal(lock)
	if _, _, err := Build(in); err == nil {
		t.Fatal("missing gateway_cluster_ip accepted")
	}
	in = inputs(t)
	in.Values = []byte(`{"control_plane_endpoint":"172.16.0.2","cloudsql_private_ip":"10.40.0.3","node_cidr":"10.99.0.0/20"}`)
	if _, _, err := Build(in); err == nil {
		t.Fatal("disagreeing node_cidr accepted")
	}
}
