package health

import (
	"slices"
	"testing"
	"time"
)

func TestDecodeProbeReport(t *testing.T) {
	node := "6f1c2b8e-1d2a-4c3b-9e8f-0a1b2c3d4e5f"
	valid := `{"probe_kind":"tcp","node_uid":"` + node + `","boot_id":"boot-1","stimulus_at":"2026-10-17T00:00:00Z","outcome":"pass","evidence_refs":["kernel:1"]}`
	if _, err := DecodeProbeReport([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown field":      `{"probe_kind":"tcp","node_uid":"` + node + `","boot_id":"b","outcome":"pass","evidence_refs":["k"],"hold":true}`,
		"non-node kind":      `{"probe_kind":"export","node_uid":"` + node + `","boot_id":"b","outcome":"pass","evidence_refs":["k"]}`,
		"missing node":       `{"probe_kind":"tcp","boot_id":"b","outcome":"pass","evidence_refs":["k"]}`,
		"null boot":          `{"probe_kind":"tcp","node_uid":"` + node + `","boot_id":null,"outcome":"pass","evidence_refs":["k"]}`,
		"pass without proof": `{"probe_kind":"tcp","node_uid":"` + node + `","boot_id":"b","outcome":"pass","evidence_refs":[]}`,
		"bad outcome":        `{"probe_kind":"tcp","node_uid":"` + node + `","boot_id":"b","outcome":"ok","evidence_refs":["k"]}`,
		"other scope":        `{"probe_kind":"tcp","scope":"global","scope_id":"*","node_uid":"` + node + `","boot_id":"b","outcome":"fail","evidence_refs":[]}`,
		"scope without id":   `{"probe_kind":"tcp","scope":"node","node_uid":"` + node + `","boot_id":"b","outcome":"fail","evidence_refs":[]}`,
		"duplicate key":      `{"probe_kind":"tcp","probe_kind":"file","node_uid":"` + node + `","boot_id":"b","outcome":"fail","evidence_refs":[]}`,
		"non canonical uuid": `{"probe_kind":"tcp","node_uid":"6F1C2B8E-1D2A-4C3B-9E8F-0A1B2C3D4E5F","boot_id":"b","outcome":"fail","evidence_refs":[]}`,
	} {
		if _, err := DecodeProbeReport([]byte(body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for _, body := range []string{
		`{"probe_kind":"file","scope":"node","scope_id":"` + node + `","node_uid":"` + node + `","boot_id":"b","outcome":"fail","evidence_refs":[]}`,
		`{"probe_kind":"export","scope":"global","scope_id":"*","outcome":"pass","evidence_refs":["write-read:1"]}`,
		`{"probe_kind":"export","scope":"node","scope_id":"` + node + `","node_uid":"` + node + `","outcome":"unknown","evidence_refs":[]}`,
		`{"probe_kind":"receipt","scope":"target","scope_id":"receiver-a","outcome":"pass","evidence_refs":["receipt:1"]}`,
	} {
		p, err := DecodeProbeReport([]byte(body))
		if err != nil || p.Scope == nil || ProbeReporter(p.ProbeKind, *p.Scope) == "" {
			t.Fatalf("valid report rejected: %s %v", body, err)
		}
	}
	p, _ := DecodeProbeReport([]byte(valid))
	if *p.Scope != "node" || *p.ScopeID != node {
		t.Fatal("node scope not derived from node_uid")
	}
}

func TestDecodeReleaseRequest(t *testing.T) {
	id := "6f1c2b8e-1d2a-4c3b-9e8f-0a1b2c3d4e5f"
	if _, err := DecodeReleaseRequest([]byte(`{"justification":"probes recovered","evidence_refs":[],"probe_result_ids":["` + id + `"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReleaseRequest([]byte(`{"justification":"activation probe passed","evidence_refs":["action:` + id + `"]}`)); err != nil {
		t.Fatal("owner-attested release rejected:", err)
	}
	r, err := DecodeReleaseRequest([]byte(`{"justification":"checked","evidence_refs":["e"],"operator_approval":{"authenticated_actor":"google:alice","approved_at":"2026-10-17T00:00:00Z","console_request_id":"req-1"}}`))
	if err != nil || r.OperatorApproval.AuthenticatedActor != "google:alice" {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"neither":         `{"justification":"x","evidence_refs":[]}`,
		"both":            `{"justification":"x","evidence_refs":[],"probe_result_ids":["` + id + `"],"operator_approval":{"authenticated_actor":"a","approved_at":"2026-10-17T00:00:00Z","console_request_id":"r"}}`,
		"blank reason":    `{"justification":" ","evidence_refs":[],"probe_result_ids":["` + id + `"]}`,
		"empty ids":       `{"justification":"x","evidence_refs":[],"probe_result_ids":[]}`,
		"duplicate ids":   `{"justification":"x","evidence_refs":[],"probe_result_ids":["` + id + `","` + id + `"]}`,
		"bad id":          `{"justification":"x","evidence_refs":[],"probe_result_ids":["nope"]}`,
		"release_ref":     `{"justification":"x","evidence_refs":[],"probe_result_ids":["` + id + `"],"release_ref":"auto:x"}`,
		"missing actor":   `{"justification":"x","evidence_refs":[],"operator_approval":{"approved_at":"2026-10-17T00:00:00Z","console_request_id":"r"}}`,
		"colon request":   `{"justification":"x","evidence_refs":[],"operator_approval":{"authenticated_actor":"a","approved_at":"2026-10-17T00:00:00Z","console_request_id":"r:1"}}`,
		"approval extras": `{"justification":"x","evidence_refs":[],"operator_approval":{"authenticated_actor":"a","approved_at":"2026-10-17T00:00:00Z","console_request_id":"r","roles":["operator"]}}`,
	} {
		if _, err := DecodeReleaseRequest([]byte(body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestVerifiedPassesAndCitation(t *testing.T) {
	created := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return created.Add(time.Duration(s) * time.Second) }
	rows := []ProbeRun{
		{ID: "p2", Kind: "process", Result: "pass", JudgedAt: at(200)}, {ID: "p1", Kind: "process", Result: "pass", JudgedAt: at(140)}, {ID: "p0", Kind: "process", Result: "pass", JudgedAt: at(-10)},
		{ID: "t2", Kind: "tcp", Result: "pass", JudgedAt: at(201)}, {ID: "t1", Kind: "tcp", Result: "pass", JudgedAt: at(141)},
		{ID: "f3", Kind: "file", Result: "pass", JudgedAt: at(190)}, {ID: "f2", Kind: "file", Result: "fail", JudgedAt: at(130)}, {ID: "f1", Kind: "file", Result: "pass", JudgedAt: at(70)},
	}
	passes := VerifiedPasses(rows, created)
	if len(passes["process"]) != 2 || len(passes["tcp"]) != 2 || len(passes["file"]) != 1 {
		t.Fatalf("runs %+v", passes)
	}
	if ProbesSatisfy(passes, NodeProbeKinds, nil, at(201)) {
		t.Fatal("a pass after a failure counted as two consecutive passes")
	}
	rows = append([]ProbeRun{{ID: "f4", Kind: "file", Result: "pass", JudgedAt: at(250)}}, rows...)
	passes = VerifiedPasses(rows, created)
	now := at(251)
	if !ProbesSatisfy(passes, NodeProbeKinds, nil, now) || !ProbesSatisfy(passes, NodeProbeKinds, []string{"p2", "p1", "t2", "t1", "f4", "f3"}, now) {
		t.Fatal("verified consecutive passes rejected")
	}
	// Recency is per kind: fresh process passes do not stand in for tcp and
	// file passes from five minutes ago.
	stale := []ProbeRun{
		{ID: "pn", Kind: "process", Result: "pass", JudgedAt: at(600)}, {ID: "pm", Kind: "process", Result: "pass", JudgedAt: at(540)},
		{ID: "tn", Kind: "tcp", Result: "pass", JudgedAt: at(300)}, {ID: "tm", Kind: "tcp", Result: "pass", JudgedAt: at(240)},
		{ID: "fn", Kind: "file", Result: "pass", JudgedAt: at(300)}, {ID: "fm", Kind: "file", Result: "pass", JudgedAt: at(240)},
	}
	if ProbesSatisfy(VerifiedPasses(stale, created), NodeProbeKinds, nil, at(601)) {
		t.Fatal("a fresh process pass released with five-minute-old tcp/file passes")
	}
	if ProbesSatisfy(passes, NodeProbeKinds, []string{"p2", "p1", "t2", "t1", "f4", "f2"}, now) || ProbesSatisfy(passes, NodeProbeKinds, []string{"p2", "p1", "t2", "t1", "f4"}, now) {
		t.Fatal("stale or partial citation accepted")
	}
	// Old passes never release: the newest must be within one interval of now.
	if ProbesSatisfy(passes, NodeProbeKinds, nil, now.Add(10*time.Hour)) {
		t.Fatal("stale passes satisfied recovery")
	}
	if ProbesSatisfy(passes, nil, nil, now) {
		t.Fatal("a scope without a probe rule was satisfied")
	}
	spaced := VerifiedPasses([]ProbeRun{{ID: "a", Kind: "tcp", Result: "pass", JudgedAt: at(300)}, {ID: "b", Kind: "tcp", Result: "pass", JudgedAt: at(100)}}, created)
	if len(spaced["tcp"]) != 1 {
		t.Fatal("passes more than one probe interval apart counted as consecutive")
	}
	// A burst of reports inside one probe interval is one stimulus window.
	burst := []ProbeRun{}
	for i := 0; i < 20; i++ {
		burst = append(burst, ProbeRun{ID: string(rune('a' + i)), Kind: "export", Result: "pass", JudgedAt: at(100 - i)})
	}
	if run := VerifiedPasses(burst, created)["export"]; len(run) != 1 {
		t.Fatalf("burst counted as %d passes", len(run))
	}
	burst = append(burst, ProbeRun{ID: "z", Kind: "export", Result: "pass", JudgedAt: at(41)})
	if run := VerifiedPasses(burst, created)["export"]; len(run) != 2 || run[1].ID != "z" {
		t.Fatalf("spaced pass after a burst not counted: %+v", run)
	}
	// A runner waiting for kernel ingest retries with the same stimulus_at:
	// the judged gap is 75s but the stimuli are 60s apart, which counts.
	retried := []ProbeRun{{ID: "r2", Kind: "tcp", Result: "pass", JudgedAt: at(160), StimulusAt: at(85)}, {ID: "r1", Kind: "tcp", Result: "pass", JudgedAt: at(85), StimulusAt: at(25)}}
	if run := VerifiedPasses(retried, created)["tcp"]; len(run) != 2 {
		t.Fatalf("delayed retry broke stimulus spacing: %+v", run)
	}
	// Two reports of stimuli 20s apart stay one window however late judged.
	close := []ProbeRun{{ID: "c2", Kind: "tcp", Result: "pass", JudgedAt: at(160), StimulusAt: at(45)}, {ID: "c1", Kind: "tcp", Result: "pass", JudgedAt: at(100), StimulusAt: at(25)}}
	if run := VerifiedPasses(close, created)["tcp"]; len(run) != 1 {
		t.Fatalf("stimuli 20s apart counted twice: %+v", run)
	}
	if len(VerifiedPasses([]ProbeRun{{ID: "u", Kind: "tcp", Result: "unknown", JudgedAt: at(10)}}, created)["tcp"]) != 0 {
		t.Fatal("unknown counted as a pass")
	}
}

func TestLatestPass(t *testing.T) {
	created := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	rows := []ProbeRun{{ID: "new-fail", Kind: "export", Result: "fail", JudgedAt: created.Add(20 * time.Second)}, {ID: "old-pass", Kind: "export", Result: "pass", JudgedAt: created.Add(10 * time.Second)}}
	if _, ok := LatestPass(rows, "export", created); ok {
		t.Fatal("a newer failure did not block single-pass release")
	}
	if p, ok := LatestPass(rows[1:], "export", created); !ok || p.ID != "old-pass" {
		t.Fatal("latest pass not found")
	}
	if _, ok := LatestPass(rows[1:], "export", created.Add(time.Minute)); ok {
		t.Fatal("a pass before the hold counted")
	}
	if _, single := ReleaseProbeKinds("global", "db_unavailable"); single || AutoReleasable("global", "db_unavailable") || AttestedOwners["db_unavailable"] != "audit-db" {
		t.Fatal("db_unavailable is owner-attested, not an export pass")
	}
	receipts := VerifiedPasses([]ProbeRun{{ID: "r3", Kind: "receipt", Result: "pass", JudgedAt: created.Add(15 * time.Second)}, {ID: "r2", Kind: "receipt", Result: "pass", JudgedAt: created.Add(10 * time.Second)}, {ID: "r1", Kind: "receipt", Result: "pass", JudgedAt: created.Add(9 * time.Second)}}, created)
	if len(receipts["receipt"]) != 2 || receipts["receipt"][1].ID != "r2" || !Recent(receipts["receipt"][0], created.Add(20*time.Second)) || Recent(receipts["receipt"][0], created.Add(30*time.Second)) {
		t.Fatalf("receipt spacing %+v", receipts)
	}
	if k, single := ReleaseProbeKinds("node", "export_lag"); !single || k[0] != "export" {
		t.Fatal("node export_lag release kind")
	}
	if !slices.Contains(SecurityReasons, "audit_integrity") || AutoReleasable("global", "audit_integrity") {
		t.Fatal("audit_integrity is a security reason")
	}
}

func TestConsoleRoles(t *testing.T) {
	if got := ConsoleRoles(" viewer, operator ,,"); len(got) != 2 || got[1] != "operator" {
		t.Fatal(got)
	}
}
