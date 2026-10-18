package join

import (
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

func fixture() Snapshot {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	local := netip.MustParseAddrPort("10.1.0.3:40000")
	vip := netip.MustParseAddrPort("10.30.0.20:8443")
	peer := netip.MustParseAddrPort("10.1.0.9:8443")
	tuple := Tuple{Local: local, Peer: vip}
	return Snapshot{ClusterUID: "cluster", AlgorithmVersion: "measured-v1",
		Connects:     []Connect{{EventID: "connect-1", NodeUID: "node", BootID: "boot", ContainerID: "full-container", ProcessExecID: "sensor-exec", NetNS: 123, SockPtr: 456, SourceTime: now, Tuple: tuple}},
		States:       []State{{EventID: "state-1", NodeUID: "node", BootID: "boot", SockPtr: 456, SourceTime: now.Add(time.Millisecond), Tuple: tuple, NewState: "ESTABLISHED"}},
		Lifecycles:   []Lifecycle{{IntervalID: "interval-1", ClusterUID: "cluster", NodeUID: "node", BootID: "boot", ContainerID: "full-container", PodUID: "pod", WorkloadID: "agent-adapters/receiver-sender", StartedAt: now.Add(-time.Hour), EndQuality: "open", EvidenceRefs: []string{"lifecycle-source-1"}}},
		Observations: []Observation{{AttemptID: "attempt-1", ActionID: "action-1", PodUID: "pod", NetNS: 123, Tuple: Tuple{Local: local, Peer: peer}, ConnectStartedAt: now.Add(-time.Second), SendStartedAt: now.Add(time.Second)}},
		Rules:        []Rule{{AlgorithmVersion: "measured-v1", MeasuredRunID: "q0-run-1", Service: vip, EndpointCIDR: netip.MustParsePrefix("10.1.0.9/32"), EndpointPort: 8443, KernelSide: VIP, AdapterSide: Endpoint}},
	}
}
func result(t *testing.T, s Snapshot) Result {
	t.Helper()
	r, err := Match(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != len(s.Connects) {
		t.Fatalf("results %d", len(r))
	}
	return r[0]
}
func assertConfidence(t *testing.T, r Result, want Confidence) {
	t.Helper()
	if r.Confidence != want {
		t.Fatalf("got %+v; want %s", r, want)
	}
	if want != Confirmed && r.Attribution != nil {
		t.Fatalf("non-confirmed attribution leaked: %+v", r)
	}
	if want == Unlinked && r.WorkloadID != "" {
		t.Fatalf("unlinked workload leaked: %+v", r)
	}
}
func TestUniqueConfirmed(t *testing.T) {
	r := result(t, fixture())
	assertConfidence(t, r, Confirmed)
	if *r.Attribution != (Attribution{"attempt-1", "action-1", "sensor-exec"}) || r.CandidateCount != 1 || r.WorkloadID != "agent-adapters/receiver-sender" {
		t.Fatalf("%+v", r)
	}
	if !reflect.DeepEqual(r.EvidenceRefs, []string{"attempt-1", "connect-1", "interval-1", "lifecycle-source-1", "q0-run-1", "state-1"}) {
		t.Fatal(r.EvidenceRefs)
	}
}
func TestEveryRequiredCondition(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Snapshot)
		want   Confidence
	}{
		{"netns", func(s *Snapshot) { s.Connects[0].NetNS++ }, WorkloadInferred},
		{"missing netns", func(s *Snapshot) { s.Connects[0].NetNS = 0 }, WorkloadInferred},
		{"source IP", func(s *Snapshot) { s.Connects[0].Tuple.Local = netip.MustParseAddrPort("10.1.0.4:40000") }, WorkloadInferred},
		{"source port", func(s *Snapshot) { s.Connects[0].Tuple.Local = netip.MustParseAddrPort("10.1.0.3:40001") }, WorkloadInferred},
		{"destination IP", func(s *Snapshot) { s.Observations[0].Tuple.Peer = netip.MustParseAddrPort("10.1.0.10:8443") }, WorkloadInferred},
		{"destination port", func(s *Snapshot) { s.Observations[0].Tuple.Peer = netip.MustParseAddrPort("10.1.0.9:443") }, WorkloadInferred},
		{"observation Pod", func(s *Snapshot) { s.Observations[0].PodUID = "other-pod" }, WorkloadInferred},
		{"untrusted sensor Pod", func(s *Snapshot) { s.Connects[0].PodUID = "other-pod" }, Unlinked},
		{"event node", func(s *Snapshot) { s.Connects[0].NodeUID = "other-node" }, Unlinked},
		{"event boot", func(s *Snapshot) { s.Connects[0].BootID = "reboot" }, Unlinked},
		{"container full ID", func(s *Snapshot) { s.Connects[0].ContainerID = "full" }, Unlinked},
		{"wrong cluster history", func(s *Snapshot) { s.Lifecycles[0].ClusterUID = "other-cluster" }, Unlinked},
		{"no history", func(s *Snapshot) { s.Lifecycles = nil }, Unlinked},
		{"no known start", func(s *Snapshot) { s.Lifecycles[0].StartedAt = time.Time{} }, Unlinked},
		{"unknown end", func(s *Snapshot) { s.Lifecycles[0].EndQuality = "unknown" }, Unlinked},
		{"missing process", func(s *Snapshot) { s.Connects[0].ProcessExecID = "" }, WorkloadInferred},
		{"missing pointer", func(s *Snapshot) { s.Connects[0].SockPtr = 0 }, WorkloadInferred},
		{"no state", func(s *Snapshot) { s.States = nil }, WorkloadInferred},
		{"state node", func(s *Snapshot) { s.States[0].NodeUID = "other-node" }, WorkloadInferred},
		{"state boot", func(s *Snapshot) { s.States[0].BootID = "old-boot" }, WorkloadInferred},
		{"state pointer", func(s *Snapshot) { s.States[0].SockPtr++ }, WorkloadInferred},
		{"state tuple", func(s *Snapshot) { s.States[0].Tuple.Peer = s.Observations[0].Tuple.Peer }, WorkloadInferred},
		{"state not established", func(s *Snapshot) { s.States[0].NewState = "CLOSE" }, WorkloadInferred},
		{"no observation", func(s *Snapshot) { s.Observations = nil }, WorkloadInferred},
		{"no Q0 rule even identical peer", func(s *Snapshot) { s.Rules = nil; s.Observations[0].Tuple.Peer = s.Connects[0].Tuple.Peer }, WorkloadInferred},
		{"unmeasured rule", func(s *Snapshot) { s.Rules[0].MeasuredRunID = "" }, WorkloadInferred},
		{"wrong algorithm rule", func(s *Snapshot) { s.Rules[0].AlgorithmVersion = "other" }, WorkloadInferred},
		{"exec gateway cap", func(s *Snapshot) { s.Lifecycles[0].WorkloadID = "agent-exec/agent-runtime" }, WorkloadInferred},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { s := fixture(); tt.change(&s); assertConfidence(t, result(t, s), tt.want) })
	}
}
func TestStateMissingDiagnostic(t *testing.T) {
	s := fixture()
	s.States = nil
	r := result(t, s)
	if r.Diagnostic != "state_event_missing" || r.CandidateCount != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestBidirectionalAmbiguity(t *testing.T) {
	t.Run("one connect two observations", func(t *testing.T) {
		s := fixture()
		o := s.Observations[0]
		o.AttemptID = "attempt-2"
		o.ActionID = "action-2"
		s.Observations = append(s.Observations, o)
		r := result(t, s)
		assertConfidence(t, r, WorkloadInferred)
		if r.CandidateCount != 2 || !reflect.DeepEqual(r.CandidateAttemptIDs, []string{"attempt-1", "attempt-2"}) {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("two connects one observation", func(t *testing.T) {
		s := fixture()
		e := s.Connects[0]
		e.EventID = "connect-2"
		s.Connects = append(s.Connects, e)
		rs, err := Match(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			assertConfidence(t, r, WorkloadInferred)
			if r.CandidateCount != 1 {
				t.Fatal(r)
			}
		}
	})
	t.Run("multiple lifecycle intervals", func(t *testing.T) {
		s := fixture()
		m := s.Lifecycles[0]
		m.IntervalID = "interval-2"
		m.PodUID = "second-pod"
		s.Lifecycles = append(s.Lifecycles, m)
		assertConfidence(t, result(t, s), Unlinked)
		// A sensor Pod hint must not choose one conflicting historical interval.
		s.Connects[0].PodUID = s.Lifecycles[0].PodUID
		assertConfidence(t, result(t, s), Unlinked)
		s.Lifecycles[1].EndQuality = "unknown"
		assertConfidence(t, result(t, s), Unlinked)
		s.Lifecycles[1].EndQuality = "open"
		s.Lifecycles[1].StartedAt = time.Time{}
		assertConfidence(t, result(t, s), Unlinked)
	})
	t.Run("late ambiguity produces new result", func(t *testing.T) {
		s := fixture()
		first := result(t, s)
		assertConfidence(t, first, Confirmed)
		e := s.Connects[0]
		e.EventID = "late-connect"
		s.Connects = append(s.Connects, e)
		assertConfidence(t, result(t, s), WorkloadInferred)
		assertConfidence(t, first, Confirmed)
	})
}

func TestConnectWindowInclusiveBounds(t *testing.T) {
	base := fixture().Connects[0].SourceTime
	for _, tt := range []struct {
		name string
		at   time.Time
		want Confidence
	}{
		{"lower", base.Add(-3 * time.Second), Confirmed}, {"upper", base.Add(3 * time.Second), Confirmed},
		{"before", base.Add(-3*time.Second - time.Nanosecond), WorkloadInferred},
		{"after", base.Add(3*time.Second + time.Nanosecond), WorkloadInferred},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := fixture()
			s.Connects[0].SourceTime = tt.at
			s.States[0].SourceTime = tt.at
			assertConfidence(t, result(t, s), tt.want)
		})
	}
}
func TestEstablishedWindowInclusiveBounds(t *testing.T) {
	base := fixture().Connects[0].SourceTime
	for _, tt := range []struct {
		name string
		at   time.Time
		want Confidence
	}{
		{"at connect", base, Confirmed}, {"at send plus skew", base.Add(3 * time.Second), Confirmed},
		{"before connect", base.Add(-time.Nanosecond), WorkloadInferred},
		{"after end", base.Add(3*time.Second + time.Nanosecond), WorkloadInferred},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := fixture()
			s.States[0].SourceTime = tt.at
			r := result(t, s)
			assertConfidence(t, r, tt.want)
			if tt.want != Confirmed && r.Diagnostic != "state_event_missing" {
				t.Fatal(r)
			}
		})
	}
}

func TestHistoricalMappingIgnoresCurrentReusedContainer(t *testing.T) {
	s := fixture()
	end := s.Connects[0].SourceTime.Add(time.Second)
	s.Lifecycles[0].EndedAt = &end
	s.Lifecycles[0].EndQuality = "observed"
	newer := s.Lifecycles[0]
	newer.IntervalID = "new-interval"
	newer.BootID = "next-boot"
	newer.PodUID = "new-pod"
	newer.WorkloadID = "agent-adapters/other"
	newer.StartedAt = end
	newer.EndedAt = nil
	newer.EndQuality = "open"
	s.Lifecycles = append(s.Lifecycles, newer)
	assertConfidence(t, result(t, s), Confirmed)
	// The current interval cannot rescue a missing historical boot.
	s.Lifecycles = s.Lifecycles[1:]
	assertConfidence(t, result(t, s), Unlinked)
}
func TestLifecycleBoundariesRemainConservative(t *testing.T) {
	s := fixture()
	at := s.Connects[0].SourceTime
	s.Lifecycles[0].StartedAt = at
	assertConfidence(t, result(t, s), Confirmed)
	s.Lifecycles[0].StartedAt = at.Add(time.Nanosecond)
	assertConfidence(t, result(t, s), Unlinked)
	s = fixture()
	s.Lifecycles[0].EndedAt = &at
	s.Lifecycles[0].EndQuality = "observed"
	assertConfidence(t, result(t, s), Unlinked)
	adjacent := s.Lifecycles[0]
	adjacent.IntervalID = "adjacent-interval"
	adjacent.StartedAt = at
	adjacent.EndedAt = nil
	adjacent.EndQuality = "open"
	s.Lifecycles = append(s.Lifecycles, adjacent)
	assertConfidence(t, result(t, s), Unlinked)
	s.Lifecycles = s.Lifecycles[:1]
	before := at.Add(time.Nanosecond)
	s.Lifecycles[0].EndedAt = &before
	assertConfidence(t, result(t, s), Confirmed)
}

func TestMeasuredDestinationDirections(t *testing.T) {
	for _, tt := range []struct {
		name            string
		kernel, adapter Side
	}{
		{"vip endpoint", VIP, Endpoint}, {"endpoint vip", Endpoint, VIP}, {"vip vip", VIP, VIP}, {"endpoint endpoint", Endpoint, Endpoint},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := fixture()
			r := &s.Rules[0]
			r.KernelSide = tt.kernel
			r.AdapterSide = tt.adapter
			vip, endpoint := r.Service, s.Observations[0].Tuple.Peer
			if tt.kernel == Endpoint {
				s.Connects[0].Tuple.Peer = endpoint
			} else {
				s.Connects[0].Tuple.Peer = vip
			}
			if tt.adapter == Endpoint {
				s.Observations[0].Tuple.Peer = endpoint
			} else {
				s.Observations[0].Tuple.Peer = vip
			}
			s.States[0].Tuple = s.Connects[0].Tuple
			assertConfidence(t, result(t, s), Confirmed)
		})
	}
	t.Run("different endpoints in broad measured CIDR", func(t *testing.T) {
		s := fixture()
		s.Rules[0].EndpointCIDR = netip.MustParsePrefix("10.1.0.0/24")
		s.Rules[0].KernelSide = Endpoint
		s.Connects[0].Tuple.Peer = netip.MustParseAddrPort("10.1.0.10:8443")
		s.States[0].Tuple = s.Connects[0].Tuple
		assertConfidence(t, result(t, s), WorkloadInferred)
	})
	t.Run("overlapping rules produce multiple targets", func(t *testing.T) {
		s := fixture()
		r := s.Rules[0]
		r.Service = netip.MustParseAddrPort("10.30.0.21:8443")
		r.MeasuredRunID = "q0-other"
		s.Rules = append(s.Rules, r)
		assertConfidence(t, result(t, s), WorkloadInferred)
	})
}

func TestInvalidVerifiedInputsFailClosed(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*Snapshot)
	}{
		{"cluster", func(s *Snapshot) { s.ClusterUID = "" }},
		{"algorithm", func(s *Snapshot) { s.AlgorithmVersion = "" }},
		{"duplicate connect", func(s *Snapshot) { s.Connects = append(s.Connects, s.Connects[0]) }},
		{"duplicate observation", func(s *Snapshot) { s.Observations = append(s.Observations, s.Observations[0]) }},
		{"duplicate state", func(s *Snapshot) { s.States = append(s.States, s.States[0]) }},
		{"same identity for connect and state", func(s *Snapshot) { s.States[0].EventID = s.Connects[0].EventID }},
		{"duplicate interval", func(s *Snapshot) { s.Lifecycles = append(s.Lifecycles, s.Lifecycles[0]) }},
		{"reversed observation time", func(s *Snapshot) {
			s.Observations[0].SendStartedAt = s.Observations[0].ConnectStartedAt.Add(-time.Second)
		}},
		{"unknown rule side", func(s *Snapshot) { s.Rules[0].KernelSide = "unspecified" }},
		{"invalid rule prefix", func(s *Snapshot) { s.Rules[0].EndpointCIDR = netip.MustParsePrefix("10.1.0.9/24") }},
		{"closed interval without end", func(s *Snapshot) { s.Lifecycles[0].EndQuality = "observed" }},
		{"missing workload", func(s *Snapshot) { s.Lifecycles[0].WorkloadID = "" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := fixture()
			tt.change(&s)
			r, err := Match(s)
			if err == nil || r != nil {
				t.Fatalf("result=%+v err=%v", r, err)
			}
		})
	}
}

func TestDeterministicAndConcurrentNoMutation(t *testing.T) {
	s := fixture()
	s.States = append(s.States, State{EventID: "state-0", NodeUID: "node", BootID: "boot", SockPtr: 456, SourceTime: s.States[0].SourceTime, Tuple: s.States[0].Tuple, NewState: "ESTABLISHED"})
	s.Lifecycles[0].EvidenceRefs = []string{"z-source", "a-source", "z-source"}
	want, err := Match(s)
	if err != nil {
		t.Fatal(err)
	}
	original := slices.Clone(s.Lifecycles[0].EvidenceRefs)
	reversed := s
	reversed.States = slices.Clone(s.States)
	slices.Reverse(reversed.States)
	got, err := Match(reversed)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("order changed result: %+v %v", got, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := Match(s)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("concurrent calculation changed: %+v %v", got, err)
			}
		}()
	}
	wg.Wait()
	if !reflect.DeepEqual(original, s.Lifecycles[0].EvidenceRefs) {
		t.Fatal("input evidence mutated")
	}
}

func TestAllInputOrdersProduceSameIndependentMatches(t *testing.T) {
	s := fixture()
	e := s.Connects[0]
	e.EventID = "connect-2"
	e.ContainerID = "second-container"
	e.SockPtr++
	e.Tuple.Local = netip.MustParseAddrPort("10.1.0.3:40001")
	s.Connects = append(s.Connects, e)
	state := s.States[0]
	state.EventID = "state-2"
	state.SockPtr = e.SockPtr
	state.Tuple = e.Tuple
	s.States = append(s.States, state)
	m := s.Lifecycles[0]
	m.IntervalID = "interval-2"
	m.ContainerID = e.ContainerID
	m.PodUID = "second-pod"
	s.Lifecycles = append(s.Lifecycles, m)
	o := s.Observations[0]
	o.AttemptID = "attempt-2"
	o.ActionID = "action-2"
	o.PodUID = m.PodUID
	o.Tuple.Local = e.Tuple.Local
	s.Observations = append(s.Observations, o)
	rule := s.Rules[0]
	rule.AlgorithmVersion = "old-v0"
	rule.MeasuredRunID = "old-run"
	s.Rules = append(s.Rules, rule)
	before, err := Match(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range before {
		assertConfidence(t, r, Confirmed)
	}
	slices.Reverse(s.Connects)
	slices.Reverse(s.States)
	slices.Reverse(s.Lifecycles)
	slices.Reverse(s.Observations)
	slices.Reverse(s.Rules)
	after, err := Match(s)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("order dependent: before=%+v after=%+v err=%v", before, after, err)
	}
}
