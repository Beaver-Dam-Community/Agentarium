package netpol

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJudgeRules(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	pod := uuid.New()
	workload := "agent-exec/runtime"
	port := 443
	dest := netip.MustParseAddr("203.0.113.10")
	connect := func(established, allowed bool) Connect {
		return Connect{KernelEventID: uuid.New(), SourceTime: now, NodeUID: uuid.New(), PodUID: &pod, WorkloadID: &workload,
			SrcIP: netip.MustParseAddr("10.0.0.5"), DestIP: dest, DestPort: port, Established: established, DestinationAllowed: allowed}
	}
	record := func(disposition, protocol string, at time.Duration, count int) Record {
		r := Record{RecordID: uuid.New(), SourceTime: now.Add(at), Disposition: disposition, Protocol: protocol, SrcIP: netip.MustParseAddr("10.0.0.5"),
			DestIP: dest, DestPort: &port, PodUID: &pod, WorkloadID: &workload, Count: count}
		if disposition == "allow" {
			r.PolicyNames = []string{"agent-exec/allow-egress"}
		}
		return r
	}
	cases := []struct {
		name                 string
		connects             []Connect
		records              []Record
		gaps                 Context
		kind, outcome        string
		ok                   bool
		limits               []string
		attempts             int64
		quality, confidence  string
		kernelIDs, recordIDs int
	}{
		{"rule1 blocked", []Connect{connect(false, false)}, []Record{record("deny", "tcp", 3*time.Second, 2)}, Context{LogGapOpen: true}, "blocked_attempt", "blocked", true, []string{}, 2, "estimated", "workload_inferred", 1, 1},
		{"rule2 established with allow record", []Connect{connect(true, false)}, []Record{record("allow", "tcp", 0, 1)}, Context{}, "unregistered_established", "established", true, []string{}, 1, "exact", "workload_inferred", 1, 1},
		{"rule2 established without record", []Connect{connect(true, false)}, nil, Context{SensorGapIDs: []string{"g1"}}, "unregistered_established", "established", true, []string{}, 1, "estimated", "workload_inferred", 1, 0},
		{"allowed established no finding", []Connect{connect(true, true)}, []Record{record("allow", "tcp", 0, 1)}, Context{}, "", "", false, nil, 0, "", "", 0, 0},
		{"deny outside match window", []Connect{connect(false, false)}, []Record{record("deny", "tcp", 8*time.Second, 1)}, Context{LogGapOpen: true}, "unmatched_attempt", "unknown", true, []string{"log_drop_unmeasured", "network_policy_log_gap"}, 1, "exact", "workload_inferred", 1, 0},
		{"rule3 tcp deny only", nil, []Record{record("deny", "tcp", 0, 4)}, Context{SensorGapIDs: []string{"gap-7"}}, "unmatched_deny", "unknown", true, []string{"gap-7"}, 4, "estimated", "workload_inferred", 0, 1},
		{"rule3 udp deny only", nil, []Record{record("deny", "udp", 0, 1)}, Context{LogGapOpen: true}, "blocked_attempt", "blocked", true, []string{"no_kernel_hook_for_protocol"}, 1, "estimated", "workload_inferred", 0, 1},
		{"allow only no finding", nil, []Record{record("allow", "tcp", 0, 1)}, Context{}, "", "", false, nil, 0, "", "", 0, 0},
	}
	for _, c := range cases {
		j, ok := Judge(c.connects, c.records, c.gaps)
		if ok != c.ok {
			t.Fatalf("%s: ok=%v", c.name, ok)
		}
		if !ok {
			continue
		}
		if j.Kind != c.kind || j.Outcome != c.outcome || !slices.Equal(j.Limitations, c.limits) || *j.AttemptCount != c.attempts || j.CountQuality != c.quality || j.Confidence != c.confidence || len(j.KernelEventIDs) != c.kernelIDs || len(j.PolicyRecordIDs) != c.recordIDs {
			t.Fatalf("%s: %+v", c.name, j)
		}
	}
	// An adapter-correlated attempt is the Correlation's business, not a finding.
	matched := connect(false, false)
	matched.AdapterMatched = true
	if _, ok := Judge([]Connect{matched}, nil, Context{}); ok {
		t.Fatal("adapter-matched attempt produced a finding")
	}
	// Without a workload mapping the finding is unlinked and carries no workload.
	unknown := connect(false, false)
	unknown.WorkloadID = nil
	if j, ok := Judge([]Connect{unknown}, nil, Context{}); !ok || j.Confidence != "unlinked" || j.WorkloadID != nil {
		t.Fatalf("unlinked: %+v", j)
	}
	// An established connect without a verified workload is never unregistered.
	anon := connect(true, false)
	anon.WorkloadID = nil
	if _, ok := Judge([]Connect{anon}, nil, Context{}); ok {
		t.Fatal("unknown workload established connection judged unregistered")
	}
	// A record whose Pod is unresolved never matches a kernel connect.
	unresolved := record("deny", "tcp", 0, 1)
	unresolved.PodUID = nil
	if Matches(connect(false, false), unresolved) {
		t.Fatal("unresolved record matched")
	}
	if MergeKey(&pod, netip.MustParseAddr("10.0.0.5"), dest, &port, "tcp") != "pod:"+pod.String()+"|203.0.113.10|443|tcp" || MergeKey(nil, netip.MustParseAddr("10.0.0.5"), dest, nil, "icmp") != "ip:10.0.0.5|203.0.113.10|-|icmp" {
		t.Fatal("merge key")
	}
}
