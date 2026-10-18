package sessions

import (
	"encoding/json"
	"net/http"
)

// ToolBudget is the COMMON ToolBudget structure. A caller sends only the
// maxima; the used_* fields must be absent or zero. The response and the
// service_session_created event carry the same applied maxima.
//
// COMMON has two forms by profile: intent_check, policy_proposal and
// discovery use read_tool_calls, model_calls and candidates and have no
// probe_actions key; activation_probe uses probe_actions only.
type ToolBudget struct {
	ReadToolCalls *ReadToolCalls `json:"read_tool_calls"`
	ModelCalls    *ModelCalls    `json:"model_calls"`
	Candidates    *Candidates    `json:"candidates"`
	ProbeActions  *ProbeActions  `json:"probe_actions,omitempty"`
}

// MarshalJSON writes the activation_probe form as {"probe_actions": ...}
// with no other key, and the other form unchanged.
func (b ToolBudget) MarshalJSON() ([]byte, error) {
	if b.ProbeActions != nil {
		return json.Marshal(struct {
			ProbeActions *ProbeActions `json:"probe_actions"`
		}{b.ProbeActions})
	}
	type plain ToolBudget
	return json.Marshal(plain(b))
}

type ReadToolCalls struct {
	PerCandidateMax int `json:"per_candidate_max"`
	UsedByCandidate int `json:"used_by_candidate"`
}

type ModelCalls struct {
	PerCandidateMax int `json:"per_candidate_max"`
	TotalMax        int `json:"total_max"`
	UsedByCandidate int `json:"used_by_candidate"`
	UsedTotal       int `json:"used_total"`
}

type Candidates struct {
	Max  int `json:"max"`
	Used int `json:"used"`
}

// budgetShape maps ToolBudget onto identity.service_session_counters for one
// profile (COMMON: evidence.* and discovery.* are read tools, model.generate
// is a model call; TASK-03 3.4 counter names).
type budgetShape struct {
	readCounter   string // "" when the profile has no read tools
	modelCounter  bool
	modelTotalMax int // per issue; equals the per-candidate max when one candidate
	candidatesMax int
	probeActions  bool // activation_probe: the probe_actions counter only
}

var budgetShapes = map[string]budgetShape{
	"intent_check":     {modelCounter: true, modelTotalMax: 1, candidatesMax: 1},
	"policy_proposal":  {readCounter: "read_tools", modelCounter: true, modelTotalMax: 16, candidatesMax: MaxCandidatesPerIssue},
	"discovery":        {readCounter: "snapshot_reads", modelCounter: true, modelTotalMax: 20, candidatesMax: 1},
	"activation_probe": {probeActions: true},
}

// ProbeActions is the activation_probe budget: probe actions per service
// session (COMMON ToolBudget; TASK-03 3.4 "probe_actions 4"). max and used
// are the max_value and used_value of the session's probe_actions counter.
type ProbeActions struct {
	Max  int `json:"max"`
	Used int `json:"used"`
}

// applyBudget returns the counter maxima and the applied ToolBudget.
// Per-candidate maxima above the profile bound are cut to it; negative values,
// nonzero used_* fields and fields the profile does not have are
// SCHEMA_INVALID.
//
// The issue-level caps (model_calls.total_max, candidates.max) are fixed to
// the profile values. A value at or above the cap is cut to the cap like the
// other fields; total_max = 0 means omitted; a value below the cap is
// rejected. They hold without extra state because
// candidates per issue are bounded by issue_candidates and each candidate's
// model counter is at most the per-candidate cap (2 x 8 = 16 for
// policy_proposal). SPEC-QUESTION: a lower issue-level cap would need
// issue-level state that no table holds, so it is rejected rather than
// silently ignored.
func applyBudget(profile string, prof Profile, req *ToolBudget) (map[string]int, *ToolBudget, error) {
	shape := budgetShapes[profile]
	counters := map[string]int{}
	for c, max := range prof.Counters {
		counters[c] = max
	}
	bad := func(msg string) error {
		return fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "tool_budget: "+msg)
	}
	capped := func(asked, max int) (int, error) {
		if asked < 0 {
			return 0, bad("negative value")
		}
		return min(asked, max), nil
	}
	totalMax, candMax := shape.modelTotalMax, shape.candidatesMax
	if req != nil {
		if r := req.ReadToolCalls; r != nil {
			if shape.readCounter == "" {
				return nil, nil, bad("profile has no read tools")
			}
			if r.UsedByCandidate != 0 {
				return nil, nil, bad("used_by_candidate is server state")
			}
			v, err := capped(r.PerCandidateMax, prof.Counters[shape.readCounter])
			if err != nil {
				return nil, nil, err
			}
			counters[shape.readCounter] = v
		}
		if m := req.ModelCalls; m != nil {
			if !shape.modelCounter {
				return nil, nil, bad("profile has no model calls")
			}
			if m.UsedByCandidate != 0 || m.UsedTotal != 0 {
				return nil, nil, bad("used_* is server state")
			}
			v, err := capped(m.PerCandidateMax, prof.Counters["model"])
			if err != nil {
				return nil, nil, err
			}
			counters["model"] = v
			if m.TotalMax != 0 && m.TotalMax < shape.modelTotalMax {
				return nil, nil, bad("model_calls.total_max below the profile cap is not supported")
			}
		}
		if p := req.ProbeActions; p != nil {
			if !shape.probeActions {
				return nil, nil, bad("profile has no probe actions")
			}
			if p.Used != 0 {
				return nil, nil, bad("probe_actions.used is server state")
			}
			v, err := capped(p.Max, prof.Counters["probe_actions"])
			if err != nil {
				return nil, nil, err
			}
			counters["probe_actions"] = v
		}
		if c := req.Candidates; c != nil {
			if shape.candidatesMax == 0 {
				return nil, nil, bad("profile has no candidates")
			}
			if c.Used != 0 {
				return nil, nil, bad("candidates.used is server state")
			}
			if c.Max < shape.candidatesMax {
				return nil, nil, bad("candidates.max below the profile cap is not supported")
			}
		}
	}
	if shape.probeActions {
		return counters, &ToolBudget{ProbeActions: &ProbeActions{Max: counters["probe_actions"]}}, nil
	}
	applied := &ToolBudget{Candidates: &Candidates{Max: candMax}}
	if shape.readCounter != "" {
		applied.ReadToolCalls = &ReadToolCalls{PerCandidateMax: counters[shape.readCounter]}
	}
	if shape.modelCounter {
		applied.ModelCalls = &ModelCalls{PerCandidateMax: counters["model"], TotalMax: totalMax}
	}
	return counters, applied, nil
}
