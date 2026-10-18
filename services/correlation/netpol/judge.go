package netpol

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TASK-10 3.7 network_policy_log starting values. Q0 must still fix the
// judge delay and match window; until then the measured limitations remain.
const (
	AlgorithmVersion = "netfinding-v1"
	JudgeDelay       = 60 * time.Second
	MatchWindow      = 7 * time.Second
	MergeWindow      = 900 * time.Second
)

// Connect is one verified kernel tcp_connect with its lifecycle mapping. Pod
// and workload are nil when the historical mapping is missing or ambiguous.
type Connect struct {
	KernelEventID      uuid.UUID
	SourceTime         time.Time
	NodeUID            uuid.UUID
	PodUID             *uuid.UUID
	PodNamespace       string
	PodName            string
	WorkloadID         *string
	SrcIP, DestIP      netip.Addr
	DestPort           int
	Established        bool
	AdapterMatched     bool // a confirmed Correlation exists for this event
	DestinationAllowed bool // TASK-06 3.1 allow table for the workload
}

// Record is a stored NetworkPolicyRecord. PodUID is set only when the
// record's (namespace, pod_name) resolved to exactly one Pod at source_time.
type Record struct {
	RecordID      uuid.UUID
	SourceTime    time.Time
	NodeUID       uuid.UUID
	Disposition   string
	Protocol      string
	SrcIP, DestIP netip.Addr
	DestPort      *int
	SrcNamespace  string
	SrcPodName    string
	DestNamespace string
	PodUID        *uuid.UUID
	WorkloadID    *string
	Count         int
	PolicyNames   []string
}

// Context carries the gaps overlapping the evaluated window on that node.
type Context struct {
	LogGapOpen   bool     // open/partially recovered/unrecoverable network_policy_log gap
	SensorGapIDs []string // kernel_sensor_export gaps
}

// Judgement is the derived NetworkFinding content (without segment fields).
type Judgement struct {
	Kind, Outcome, CountQuality, Confidence, Reason string
	AttemptCount                                    *int64
	Limitations                                     []string
	KernelEventIDs, PolicyRecordIDs                 []uuid.UUID
	WindowStart, WindowEnd                          time.Time
	PodUID                                          *uuid.UUID
	WorkloadID                                      *string
	NodeUID                                         uuid.UUID
}

// Matches applies the 3.7 match key: unique Pod, destination, tcp and a
// MatchWindow of the record time. Ports and netns are not compared.
func Matches(c Connect, r Record) bool {
	if c.PodUID == nil || r.PodUID == nil || *c.PodUID != *r.PodUID || r.Protocol != "tcp" || r.DestPort == nil {
		return false
	}
	if c.DestIP != r.DestIP || c.DestPort != *r.DestPort {
		return false
	}
	d := c.SourceTime.Sub(r.SourceTime)
	return d >= -MatchWindow && d <= MatchWindow
}

// MergeKey is the deterministic finding identity: source Pod (else source IP),
// destination address, port and protocol. Kind is never part of it.
func MergeKey(pod *uuid.UUID, src, dest netip.Addr, port *int, protocol string) string {
	source := "ip:" + src.String()
	if pod != nil {
		source = "pod:" + pod.String()
	}
	p := "-"
	if port != nil {
		p = fmt.Sprint(*port)
	}
	return strings.Join([]string{source, dest.String(), p, protocol}, "|")
}

func addLimit(list []string, v string) []string {
	if !slices.Contains(list, v) {
		list = append(list, v)
	}
	return list
}

// Judge evaluates the 3.7 rules over the full input set of one merge key.
// It returns false when the rules define no finding (established allowed
// connections, adapter-correlated attempts, or allow-only records).
func Judge(connects []Connect, records []Record, gaps Context) (Judgement, bool) {
	var j Judgement
	limits := []string{}
	if gaps.LogGapOpen {
		limits = addLimit(limits, "network_policy_log_gap")
	}
	quality := "exact"
	if len(gaps.SensorGapIDs) > 0 {
		quality = "estimated"
	}
	matching := func(disposition string) []Record {
		out := []Record{}
		for _, r := range records {
			if r.Disposition != disposition {
				continue
			}
			for _, c := range connects {
				if Matches(c, r) {
					out = append(out, r)
					break
				}
			}
		}
		return out
	}
	sum := func(rs []Record) *int64 {
		var n int64
		for _, r := range rs {
			n += int64(r.Count)
		}
		return &n
	}
	var established, unregistered []Connect
	for _, c := range connects {
		if c.Established {
			established = append(established, c)
			// Without a verified workload the allow table cannot be applied, so
			// the connection is never called unregistered.
			if !c.DestinationAllowed && c.WorkloadID != nil {
				unregistered = append(unregistered, c)
			}
		}
	}
	var used []Record
	switch {
	case len(established) > 0:
		if len(unregistered) == 0 {
			return j, false
		}
		// Rule 2: the same event as the unregistered_connect_established risk
		// event. Allow records only add the opening policy names as evidence.
		used = matching("allow")
		n := int64(len(connects))
		j.Kind, j.Outcome, j.AttemptCount, j.CountQuality = "unregistered_established", "established", &n, quality
		names := []string{}
		for _, r := range used {
			names = append(names, r.PolicyNames...)
		}
		slices.Sort(names)
		j.Reason = "tcp_connect established to a destination outside the workload allow table"
		if len(names) > 0 {
			j.Reason += "; allowed by " + strings.Join(slices.Compact(names), ",")
		}
	case len(connects) > 0:
		if denies := matching("deny"); len(denies) > 0 {
			// Rule 1: attempt without establishment and a matching deny record.
			used = denies
			j.Kind, j.Outcome, j.AttemptCount, j.CountQuality = "blocked_attempt", "blocked", sum(denies), "estimated"
			j.Reason = "tcp_connect not established and a matching deny record exists"
			limits = slices.DeleteFunc(limits, func(s string) bool { return s == "network_policy_log_gap" })
			break
		}
		attempts := []Connect{}
		for _, c := range connects {
			if !c.AdapterMatched {
				attempts = append(attempts, c)
			}
		}
		if len(attempts) == 0 {
			return j, false
		}
		connects = attempts
		// Rule 4: never a violation or bypass claim.
		n := int64(len(connects))
		j.Kind, j.Outcome, j.AttemptCount, j.CountQuality = "unmatched_attempt", "unknown", &n, quality
		j.Reason = "tcp_connect not established, no matching deny record or adapter observation"
		limits = addLimit(limits, "log_drop_unmeasured")
	default:
		denies := []Record{}
		for _, r := range records {
			if r.Disposition == "deny" {
				denies = append(denies, r)
			}
		}
		if len(denies) == 0 {
			return j, false
		}
		used = denies
		if denies[0].Protocol == "tcp" {
			// Rule 3 (tcp): sensor gap candidate; the record alone is unknown.
			j.Kind, j.Outcome = "unmatched_deny", "unknown"
			j.Reason = "tcp deny record without a matching kernel connect"
			for _, id := range gaps.SensorGapIDs {
				limits = addLimit(limits, id)
			}
		} else {
			j.Kind, j.Outcome = "blocked_attempt", "blocked"
			j.Reason = denies[0].Protocol + " deny record; the sensor has no hook for this protocol"
			limits = addLimit(limits, "no_kernel_hook_for_protocol")
			limits = slices.DeleteFunc(limits, func(s string) bool { return s == "network_policy_log_gap" })
		}
		j.AttemptCount, j.CountQuality = sum(denies), "estimated"
	}
	for _, c := range connects {
		j.KernelEventIDs = append(j.KernelEventIDs, c.KernelEventID)
		j.widen(c.SourceTime)
		j.identity(c.PodUID, c.WorkloadID, c.NodeUID)
	}
	for _, r := range used {
		j.PolicyRecordIDs = append(j.PolicyRecordIDs, r.RecordID)
		j.widen(r.SourceTime)
		j.identity(r.PodUID, r.WorkloadID, r.NodeUID)
	}
	sortIDs(j.KernelEventIDs)
	sortIDs(j.PolicyRecordIDs)
	slices.Sort(limits)
	j.Limitations = limits
	j.Confidence = "unlinked"
	if j.WorkloadID != nil {
		j.Confidence = "workload_inferred"
	}
	return j, true
}

func (j *Judgement) widen(t time.Time) {
	if j.WindowStart.IsZero() || t.Before(j.WindowStart) {
		j.WindowStart = t
	}
	if t.After(j.WindowEnd) {
		j.WindowEnd = t
	}
}

func (j *Judgement) identity(pod *uuid.UUID, workload *string, node uuid.UUID) {
	if j.PodUID == nil && pod != nil {
		j.PodUID = pod
	}
	if j.WorkloadID == nil && workload != nil {
		j.WorkloadID = workload
	}
	if j.NodeUID == uuid.Nil {
		j.NodeUID = node
	}
}

func sortIDs(ids []uuid.UUID) {
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
}
