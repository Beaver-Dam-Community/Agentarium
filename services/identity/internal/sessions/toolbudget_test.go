package sessions

import (
	"encoding/json"
	"testing"
)

// The response and the service_session_created event carry the applied
// tool_budget, which is never null (COMMON ToolBudget; TASK-07 event
// registry). activation_probe has the probe_actions form only.
func TestAppliedToolBudgetNotNull(t *testing.T) {
	want := map[string]string{
		"intent_check":     `{"read_tool_calls":null,"model_calls":{"per_candidate_max":1,"total_max":1,"used_by_candidate":0,"used_total":0},"candidates":{"max":1,"used":0}}`,
		"policy_proposal":  `{"read_tool_calls":{"per_candidate_max":6,"used_by_candidate":0},"model_calls":{"per_candidate_max":8,"total_max":16,"used_by_candidate":0,"used_total":0},"candidates":{"max":2,"used":0}}`,
		"discovery":        `{"read_tool_calls":{"per_candidate_max":50,"used_by_candidate":0},"model_calls":{"per_candidate_max":20,"total_max":20,"used_by_candidate":0,"used_total":0},"candidates":{"max":1,"used":0}}`,
		"activation_probe": `{"probe_actions":{"max":4,"used":0}}`,
	}
	if len(want) != len(Profiles) {
		t.Fatalf("profiles %d, cases %d", len(Profiles), len(want))
	}
	for name, prof := range Profiles {
		counters, applied, err := applyBudget(name, prof, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, err := json.Marshal(applied)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != want[name] {
			t.Errorf("%s tool_budget %s, want %s", name, b, want[name])
		}
		if name == "activation_probe" && applied.ProbeActions.Max != counters["probe_actions"] {
			t.Errorf("probe max %d, counter %d", applied.ProbeActions.Max, counters["probe_actions"])
		}
	}
}

// A caller's probe_actions.max is cut to the profile cap 4 like the other
// maxima; the other families, used and negative values are SCHEMA_INVALID,
// and no other profile takes probe_actions.
func TestProbeActionsBudget(t *testing.T) {
	prof := Profiles["activation_probe"]
	for asked, want := range map[int]int{2: 2, 4: 4, 9: 4, 0: 0} {
		counters, applied, err := applyBudget("activation_probe", prof, &ToolBudget{ProbeActions: &ProbeActions{Max: asked}})
		if err != nil {
			t.Fatalf("max %d: %v", asked, err)
		}
		if counters["probe_actions"] != want || applied.ProbeActions.Max != want || applied.ProbeActions.Used != 0 {
			t.Errorf("max %d: counter %d, applied %+v", asked, counters["probe_actions"], applied.ProbeActions)
		}
	}
	bad := map[string]struct {
		profile string
		req     ToolBudget
	}{
		"used set":         {"activation_probe", ToolBudget{ProbeActions: &ProbeActions{Max: 2, Used: 1}}},
		"negative":         {"activation_probe", ToolBudget{ProbeActions: &ProbeActions{Max: -1}}},
		"model on probe":   {"activation_probe", ToolBudget{ModelCalls: &ModelCalls{PerCandidateMax: 1}}},
		"probe on another": {"intent_check", ToolBudget{ProbeActions: &ProbeActions{Max: 1}}},
	}
	for name, c := range bad {
		if _, _, err := applyBudget(c.profile, Profiles[c.profile], &c.req); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
