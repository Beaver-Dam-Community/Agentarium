package join

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type candidate struct {
	observation int
	evidence    []string
}
type prepared struct {
	result     Result
	mapping    *Lifecycle
	baseCount  int
	candidates []candidate
}

type lifecycleKey struct{ node, boot, container string }
type observationKey struct {
	netns uint64
	local netip.AddrPort
	pod   string
}
type stateKey struct {
	node, boot string
	pointer    uint64
	tuple      Tuple
}

// Match is deterministic, has no I/O and does not retain or mutate its inputs.
// Recomputing with late evidence returns a new calculation; prior persisted
// revisions must be retained by the future storage adapter.
func Match(s Snapshot) ([]Result, error) {
	if err := validate(s); err != nil {
		return nil, err
	}
	preparedEvents := make([]prepared, len(s.Connects))
	reverse := make([]int, len(s.Observations))
	lifecycleIndex := map[lifecycleKey][]int{}
	for i, m := range s.Lifecycles {
		if m.ClusterUID == s.ClusterUID {
			key := lifecycleKey{m.NodeUID, m.BootID, m.ContainerID}
			lifecycleIndex[key] = append(lifecycleIndex[key], i)
		}
	}
	observationIndex := map[observationKey][]int{}
	for i, o := range s.Observations {
		key := observationKey{o.NetNS, o.Tuple.Local, o.PodUID}
		observationIndex[key] = append(observationIndex[key], i)
	}
	stateIndex := map[stateKey][]State{}
	for _, state := range s.States {
		if state.NewState == "ESTABLISHED" {
			key := stateKey{state.NodeUID, state.BootID, state.SockPtr, state.Tuple}
			stateIndex[key] = append(stateIndex[key], state)
		}
	}
	for i, e := range s.Connects {
		p := &preparedEvents[i]
		p.result = Result{KernelEventID: e.EventID, Confidence: Unlinked, AlgorithmVersion: s.AlgorithmVersion,
			CandidateAttemptIDs: []string{}, EvidenceRefs: []string{}, Limitations: []string{}}
		mappings := mappingsAt(s, e, lifecycleIndex[lifecycleKey{e.NodeUID, e.BootID, e.ContainerID}])
		if len(mappings) != 1 || (e.PodUID != "" && e.PodUID != s.Lifecycles[mappings[0]].PodUID) {
			p.result.Diagnostic = "historical workload mapping missing or ambiguous"
			continue
		}
		p.mapping = &s.Lifecycles[mappings[0]]
		p.result.WorkloadID = p.mapping.WorkloadID
		p.result.Confidence = WorkloadInferred
		p.result.EvidenceRefs = append(p.result.EvidenceRefs, p.mapping.EvidenceRefs...)
		p.result.EvidenceRefs = append(p.result.EvidenceRefs, p.mapping.IntervalID, e.EventID)
		// Exec Pod -> gateway lacks a transport recorder in MVP. Ignore even an
		// erroneously supplied observation rather than turn this path into confirmed.
		if strings.HasPrefix(p.mapping.WorkloadID, "agent-exec/") {
			p.result.Diagnostic = "exec workload has no adapter transport attribution"
			p.result.Limitations = append(p.result.Limitations, "exec-to-gateway confidence is capped at workload_inferred")
			continue
		}
		for _, j := range observationIndex[observationKey{e.NetNS, e.Tuple.Local, p.mapping.PodUID}] {
			o := s.Observations[j]
			if e.NetNS == 0 || e.NetNS != o.NetNS || e.Tuple.Local != o.Tuple.Local ||
				p.mapping.PodUID != o.PodUID || !within(e.SourceTime, o.ConnectStartedAt.Add(-ClockSkew), o.SendStartedAt.Add(ClockSkew)) {
				continue
			}
			refs, ok := destinations(s.Rules, s.AlgorithmVersion, e.Tuple.Peer, o.Tuple.Peer)
			if !ok {
				continue
			}
			p.baseCount++
			established := statesFor(stateIndex[stateKey{e.NodeUID, e.BootID, e.SockPtr, e.Tuple}], e, o.SendStartedAt.Add(ClockSkew))
			if len(established) == 0 {
				continue
			}
			refs = append(refs, established...)
			refs = append(refs, o.AttemptID)
			p.candidates = append(p.candidates, candidate{j, refs})
			reverse[j]++
		}
	}
	results := make([]Result, 0, len(preparedEvents))
	for i := range preparedEvents {
		p := &preparedEvents[i]
		r := &p.result
		r.CandidateCount = len(p.candidates)
		for _, c := range p.candidates {
			r.CandidateAttemptIDs = append(r.CandidateAttemptIDs, s.Observations[c.observation].AttemptID)
			r.EvidenceRefs = append(r.EvidenceRefs, c.evidence...)
		}
		if p.mapping != nil && r.Diagnostic == "" {
			switch {
			case len(p.candidates) == 1 && reverse[p.candidates[0].observation] == 1 && s.Connects[i].ProcessExecID != "":
				o := s.Observations[p.candidates[0].observation]
				r.Confidence = Confirmed
				r.Attribution = &Attribution{AttemptID: o.AttemptID, ActionID: o.ActionID, ProcessExecID: s.Connects[i].ProcessExecID}
				r.Diagnostic = "unique measured socket match in both directions"
			case len(p.candidates) == 0 && p.baseCount > 0:
				r.Diagnostic = "state_event_missing"
			case len(p.candidates) > 0:
				r.Diagnostic = "socket attribution ambiguous or process identity missing"
			default:
				r.Diagnostic = "no observation matches measured socket conditions"
			}
		}
		r.CandidateAttemptIDs = sortedUnique(r.CandidateAttemptIDs)
		r.EvidenceRefs = sortedUnique(r.EvidenceRefs)
		results = append(results, *r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].KernelEventID < results[j].KernelEventID })
	return results, nil
}

func within(t, start, end time.Time) bool { return !t.IsZero() && !t.Before(start) && !t.After(end) }

func mappingsAt(s Snapshot, e Connect, indexes []int) []int {
	var matches []int
	if e.NodeUID == "" || e.BootID == "" || e.ContainerID == "" || e.SourceTime.IsZero() {
		return matches
	}
	for _, i := range indexes {
		m := s.Lifecycles[i]
		if m.ClusterUID != s.ClusterUID || m.NodeUID != e.NodeUID || m.BootID != e.BootID || m.ContainerID != e.ContainerID ||
			(!m.StartedAt.IsZero() && e.SourceTime.Before(m.StartedAt)) {
			continue
		}
		if m.StartedAt.IsZero() || m.EndQuality == "unknown" {
			// Incomplete history cannot be silently discarded to manufacture
			// a unique mapping from a second overlapping interval.
			return nil
		}
		// The spec does not define endpoint inclusivity. Exact end-boundary data
		// is deliberately not promoted until the interval adapter contract settles it.
		if m.EndedAt != nil {
			if e.SourceTime.Equal(*m.EndedAt) {
				// A neighboring interval beginning at this instant cannot resolve
				// the old interval's unspecified end-boundary semantics either.
				return nil
			}
			if e.SourceTime.After(*m.EndedAt) {
				continue
			}
		}
		matches = append(matches, i)
	}
	return matches
}

func statesFor(states []State, e Connect, end time.Time) []string {
	var refs []string
	if e.SockPtr == 0 {
		return refs
	}
	for _, state := range states {
		if state.NewState == "ESTABLISHED" && state.NodeUID == e.NodeUID && state.BootID == e.BootID &&
			state.SockPtr == e.SockPtr && state.Tuple == e.Tuple && within(state.SourceTime, e.SourceTime, end) {
			refs = append(refs, state.EventID)
		}
	}
	return refs
}

// Each side must normalize unambiguously to the same measured service. When
// both sides report endpoints, also retain the concrete endpoint: a broad CIDR
// must not equate two distinct servers merely because both back the same VIP.
func destinations(rules []Rule, version string, kernel, adapter netip.AddrPort) ([]string, bool) {
	kernelTargets, adapterTargets := map[netip.AddrPort]bool{}, map[netip.AddrPort]bool{}
	var refs []string
	for _, r := range rules {
		if r.AlgorithmVersion != version || r.MeasuredRunID == "" {
			continue
		}
		k, a := sideMatches(kernel, r.KernelSide, r), sideMatches(adapter, r.AdapterSide, r)
		if k {
			kernelTargets[r.Service] = true
		}
		if a {
			adapterTargets[r.Service] = true
		}
		if k && a && !(r.KernelSide == Endpoint && r.AdapterSide == Endpoint && kernel != adapter) {
			refs = append(refs, r.MeasuredRunID)
		}
	}
	if len(kernelTargets) != 1 || len(adapterTargets) != 1 || len(refs) == 0 {
		return nil, false
	}
	for target := range kernelTargets {
		if !adapterTargets[target] {
			return nil, false
		}
	}
	return sortedUnique(refs), true
}
func sideMatches(address netip.AddrPort, side Side, r Rule) bool {
	if side == VIP {
		return address == r.Service
	}
	return address.Port() == r.EndpointPort && r.EndpointCIDR.Contains(address.Addr())
}
func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	sort.Strings(in)
	out := in[:0]
	for _, v := range in {
		if v != "" && (len(out) == 0 || out[len(out)-1] != v) {
			out = append(out, v)
		}
	}
	return out
}

func validate(s Snapshot) error {
	if s.ClusterUID == "" || s.AlgorithmVersion == "" {
		return errors.New("cluster and algorithm version required")
	}
	unique := func(kind string, ids []string) error {
		seen := map[string]bool{}
		for _, id := range ids {
			if id == "" || seen[id] {
				return fmt.Errorf("missing or duplicate %s identity", kind)
			}
			seen[id] = true
		}
		return nil
	}
	ids := make([]string, len(s.Connects), len(s.Connects)+len(s.States))
	for i, e := range s.Connects {
		ids[i] = e.EventID
	}
	for _, e := range s.States {
		ids = append(ids, e.EventID)
	}
	if err := unique("kernel event", ids); err != nil {
		return err
	}
	ids = make([]string, len(s.Observations))
	for i, o := range s.Observations {
		ids[i] = o.AttemptID
		if o.ActionID == "" || o.PodUID == "" || o.NetNS == 0 || !validTuple(o.Tuple) || o.ConnectStartedAt.IsZero() || o.SendStartedAt.Before(o.ConnectStartedAt) {
			return errors.New("invalid verified observation")
		}
	}
	if err := unique("attempt", ids); err != nil {
		return err
	}
	ids = make([]string, len(s.Lifecycles))
	for i, m := range s.Lifecycles {
		ids[i] = m.IntervalID
		parts := strings.Split(m.WorkloadID, "/")
		if m.PodUID == "" || len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return errors.New("invalid verified lifecycle identity")
		}
		switch m.EndQuality {
		case "open":
			if m.EndedAt != nil {
				return errors.New("open interval has an end")
			}
		case "observed", "inferred_from_other_source":
			if m.EndedAt == nil || m.EndedAt.Before(m.StartedAt) {
				return errors.New("invalid closed interval")
			}
		case "unknown":
		default:
			return errors.New("invalid interval end quality")
		}
	}
	if err := unique("lifecycle", ids); err != nil {
		return err
	}
	for _, r := range s.Rules {
		if r.AlgorithmVersion == "" || !validAddress(r.Service) || !r.EndpointCIDR.IsValid() || r.EndpointCIDR != r.EndpointCIDR.Masked() || r.EndpointPort == 0 ||
			(r.KernelSide != VIP && r.KernelSide != Endpoint) || (r.AdapterSide != VIP && r.AdapterSide != Endpoint) {
			return errors.New("invalid measured normalization rule")
		}
	}
	return nil
}
func validAddress(a netip.AddrPort) bool {
	return a.IsValid() && a.Port() != 0 && a.Addr().Zone() == "" && !a.Addr().IsUnspecified()
}
func validTuple(t Tuple) bool { return validAddress(t.Local) && validAddress(t.Peer) }
