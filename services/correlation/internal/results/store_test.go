package results

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAttributionBoundary(t *testing.T) {
	workload := "agent-adapters/receiver-sender"
	action, attempt := uuid.New(), uuid.New()
	base := Result{KernelEventID: uuid.New(), Confidence: "confirmed", ActionID: &action, AttemptID: &attempt, WorkloadID: &workload, CandidateCount: 1, Method: "fixture-method", AlgorithmVersion: "fixture-v1", Reason: "fixture reason", EvidenceRefs: []string{"kernel-ref"}}
	if err := validate(base); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Result)
	}{
		{"ambiguous confirmed", func(r *Result) { r.CandidateCount = 2 }},
		{"no attempt", func(r *Result) { r.AttemptID = nil }},
		{"no action", func(r *Result) { r.ActionID = nil }},
		{"no workload", func(r *Result) { r.WorkloadID = nil }},
		{"unlinked action", func(r *Result) { r.Confidence = "unlinked" }},
		{"inferred action", func(r *Result) { r.Confidence = "workload_inferred" }},
		{"nil kernel", func(r *Result) { r.KernelEventID = uuid.Nil }},
		{"unknown confidence", func(r *Result) { r.Confidence = "probable" }},
		{"oversized evidence", func(r *Result) { r.EvidenceRefs = []string{strings.Repeat("x", 16385)} }},
		{"nul method", func(r *Result) { r.Method = "fixture\x00method" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := base
			test.mutate(&r)
			if validate(r) == nil {
				t.Fatal("accepted invalid attribution")
			}
		})
	}
	base.Confidence = "workload_inferred"
	base.ActionID = nil
	base.AttemptID = nil
	base.CandidateCount = 2
	if err := validate(base); err != nil {
		t.Fatal(err)
	}
	base.Confidence = "unlinked"
	base.WorkloadID = nil
	if err := validate(base); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizationDoesNotAliasCalculation(t *testing.T) {
	workload := "agent-adapters/receiver-sender"
	action := uuid.New()
	attempt := uuid.New()
	in := Result{ActionID: &action, AttemptID: &attempt, WorkloadID: &workload, EvidenceRefs: []string{"b", "a", "b"}, Limitations: []string{"z", "a"}}
	out := normalize(in)
	if strings.Join(in.EvidenceRefs, ",") != "b,a,b" || strings.Join(out.EvidenceRefs, ",") != "a,b" {
		t.Fatal("normalization changed original evidence")
	}
	*out.WorkloadID = "changed"
	*out.ActionID = uuid.Nil
	*out.AttemptID = uuid.Nil
	out.EvidenceRefs[0] = "changed"
	out.Limitations[0] = "changed"
	if workload != "agent-adapters/receiver-sender" || action == uuid.Nil || attempt == uuid.Nil || in.EvidenceRefs[0] != "b" || in.Limitations[0] != "z" {
		t.Fatal("stored result aliases calculation")
	}
	if !equivalent(Result{}, Result{EvidenceRefs: []string{}, Limitations: []string{}}) {
		t.Fatal("empty sets create a duplicate revision")
	}
}
