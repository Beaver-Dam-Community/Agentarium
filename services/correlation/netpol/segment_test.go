package netpol

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
)

func testEnvironment() Environment {
	return Environment{
		LockDigest: strings.Repeat("a", 64),
		PodsRange:  netip.MustParsePrefix("10.20.0.0/16"), ServicesRange: netip.MustParsePrefix("10.30.0.0/20"), NodeCIDR: netip.MustParsePrefix("10.10.0.0/20"),
		ControlPlane: netip.MustParseAddr("10.40.0.2"), CloudSQL: netip.MustParseAddr("10.50.0.2"), Gateway: netip.MustParseAddr("10.30.0.20"), DNS: netip.MustParseAddr("10.30.0.10"),
		Metadata: []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32")}, PGA: []netip.Prefix{netip.MustParsePrefix("199.36.153.8/30")},
		AllowedTargets: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("10.20.0.0/16")},
	}
}

func TestDestinationRules(t *testing.T) {
	c, err := NewClassifier(testEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, ip, namespace, exec, control, boundary string
	}{
		{"metadata", "169.254.169.254", "agent-targets", "exec_to_metadata", "control_to_control", "internal"},
		{"apiserver", "10.40.0.2", "agent-exec", "exec_to_cluster_api", "control_to_control", "internal"},
		{"pga", "199.36.153.9", "agent-control", "exec_direct_external", "control_to_google_api", "external"},
		{"exec", "10.20.0.3", "agent-exec", "exec_to_exec", "unclassified", "internal"},
		{"control", "10.20.0.3", "agent-control", "exec_to_control", "control_to_control", "internal"},
		{"adapter", "10.20.0.3", "agent-adapters", "exec_to_control", "control_to_control", "internal"},
		{"observe", "10.20.0.3", "agent-observe", "exec_to_control", "control_to_control", "internal"},
		{"release", "10.20.0.3", "agent-release", "exec_to_control", "control_to_control", "internal"},
		{"sensor", "10.20.0.3", "agent-sensors", "exec_to_control", "control_to_control", "internal"},
		{"target", "10.20.0.3", "agent-targets", "exec_to_internal_other", "control_to_target", "internal"},
		{"cloudsql", "10.50.0.2", "", "exec_to_internal_other", "control_to_control", "internal"},
		{"system", "10.20.0.3", "kube-system", "exec_to_internal_other", "control_to_control", "internal"},
		{"gateway", "10.30.0.20", "", "exec_to_control", "control_to_control", "internal"},
		{"dns", "10.30.0.10", "", "exec_to_internal_other", "control_to_control", "internal"},
		{"pod-range-before-catalog", "10.20.0.3", "", "exec_to_internal_other", "unclassified", "internal"},
		{"unknown-service", "10.30.0.40", "", "exec_to_internal_other", "unclassified", "internal"},
		{"node-range", "10.10.0.3", "", "exec_to_internal_other", "unclassified", "internal"},
		{"registered-external", "203.0.113.5", "", "exec_direct_external", "control_to_target", "external"},
		{"other-external", "198.51.100.5", "", "exec_direct_external", "control_to_external", "external"},
		// A private address outside the lock's known networks is not inferred internal.
		{"private-but-unlisted", "192.168.200.2", "", "exec_direct_external", "control_to_external", "external"},
		{"namespace-before-service-ip", "10.30.0.20", "agent-exec", "exec_to_exec", "unclassified", "internal"},
		{"unknown-namespace-no-service-fallback", "10.30.0.20", "other", "exec_to_internal_other", "unclassified", "internal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, source := range []struct{ namespace, want string }{
				{"agent-exec", tc.exec}, {"agent-control", tc.control}, {"agent-adapters", tc.control}, {"agent-observe", tc.control}, {"agent-release", tc.control},
				{"agent-sensors", "unclassified"}, {"kube-system", "unclassified"}, {"other", "unclassified"},
			} {
				got := c.Classify(Endpoint{source.namespace, "pod"}, tc.ip, Endpoint{Namespace: tc.namespace})
				if got.NetworkSegment != source.want || got.BoundaryCrossing != tc.boundary || got.RuleVersion != RuleVersion {
					t.Errorf("source=%s got=%+v want=%s/%s", source.namespace, got, source.want, tc.boundary)
				}
			}
		})
	}
}

func TestEvidenceAndUnknownBoundaries(t *testing.T) {
	c, _ := NewClassifier(testEnvironment())
	source := Endpoint{"agent-exec", "pod"}
	for _, ip := range []string{"10.30.0.20", "10.30.0.10"} {
		got := c.Classify(source, ip, Endpoint{})
		if !strings.Contains(got.Reason, "sha256:"+testEnvironment().LockDigest) || len(got.Limitations) != 0 {
			t.Fatalf("pinned Service evidence absent: %+v", got)
		}
	}
	got := c.Classify(source, "10.30.0.40", Endpoint{})
	if !slices.Equal(got.Limitations, []string{"dnat_unmeasured"}) {
		t.Fatal(got)
	}
	for _, namespace := range []string{"agent-control", "other"} {
		got = c.Classify(source, "10.30.0.40", Endpoint{Namespace: namespace})
		if len(got.Limitations) != 0 {
			t.Fatal(got)
		}
	}
	got = c.Classify(Endpoint{Namespace: "agent-exec"}, "10.30.0.20", Endpoint{})
	if got.NetworkSegment != "unclassified" || got.BoundaryCrossing != "internal" {
		t.Fatal(got)
	}
	for _, bad := range []string{"", "not-an-ip", "example.com", "https://10.30.0.20", "10.30.0.20:8443", " 10.30.0.20", "::ffff:10.30.0.20", "fe80::1%eth0"} {
		got = c.Classify(source, bad, Endpoint{Namespace: "agent-control"})
		if got.NetworkSegment != "unclassified" || got.BoundaryCrossing != "unknown" {
			t.Fatalf("%q: %+v", bad, got)
		}
	}
	for _, missing := range []*Classifier{nil, {}} {
		got = missing.Classify(source, "10.30.0.20", Endpoint{})
		if got.NetworkSegment != "unclassified" || got.BoundaryCrossing != "unknown" {
			t.Fatal(got)
		}
	}
}

func TestEnvironmentValidationAndSnapshot(t *testing.T) {
	for name, mutate := range map[string]func(*Environment){
		"digest":                        func(e *Environment) { e.LockDigest = strings.Repeat("z", 64) },
		"uppercase-digest":              func(e *Environment) { e.LockDigest = strings.Repeat("A", 64) },
		"network":                       func(e *Environment) { e.NodeCIDR = netip.Prefix{} },
		"unmasked-network":              func(e *Environment) { e.PodsRange = netip.MustParsePrefix("10.20.1.2/16") },
		"endpoint":                      func(e *Environment) { e.ControlPlane = netip.Addr{} },
		"metadata":                      func(e *Environment) { e.Metadata = nil },
		"pga":                           func(e *Environment) { e.PGA = nil },
		"target":                        func(e *Environment) { e.AllowedTargets = []netip.Prefix{{}} },
		"gateway-outside-service-range": func(e *Environment) { e.Gateway = netip.MustParseAddr("10.20.0.1") },
		"same-service-ips":              func(e *Environment) { e.DNS = e.Gateway },
	} {
		t.Run(name, func(t *testing.T) {
			e := testEnvironment()
			mutate(&e)
			if _, err := NewClassifier(e); err == nil {
				t.Fatal("accepted invalid environment")
			}
		})
	}
	env := testEnvironment()
	c, err := NewClassifier(env)
	if err != nil {
		t.Fatal(err)
	}
	env.Metadata[0] = netip.MustParsePrefix("0.0.0.0/0")
	env.PGA[0] = netip.MustParsePrefix("0.0.0.0/0")
	env.AllowedTargets[0] = netip.MustParsePrefix("0.0.0.0/0")
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := c.Classify(Endpoint{"agent-control", "pod"}, "198.51.100.2", Endpoint{})
			if got.NetworkSegment != "control_to_external" {
				t.Error(got)
			}
		}()
	}
	wg.Wait()
}
