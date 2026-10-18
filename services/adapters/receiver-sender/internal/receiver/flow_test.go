package receiver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
	"github.com/Beaver-Dam-Community/Agentarium/services/adapters/receiver-sender/internal/receiver"
)

const okPayload = `{"summary":"3 pods restarted","email":null}`

func indexOf(ops []string, s string) int { return slices.Index(ops, s) }

// Approved action, 201 from the receiver: reservation → claim → one send →
// ① raise → ② response_received → ③ action_results → ④ completed.
func TestAcceptedCommitOrder(t *testing.T) {
	h := newHarness(t, withResponseClass("synthetic"))
	d, a := h.action(okPayload)
	row := h.run(d, a)
	if row.State != execute.StateCompleted {
		t.Fatalf("state %s, ops %v", row.State, h.log.list())
	}
	if h.recv.count.Load() != 1 {
		t.Fatalf("receiver got %d requests", h.recv.count.Load())
	}
	in := h.inputs.in[d]
	if string(h.recv.bodies[0]) != string(in.Content.ContentBytes) {
		t.Fatalf("sent body %s, approved %s", h.recv.bodies[0], in.Content.ContentBytes)
	}
	hd := h.recv.headers[0]
	if hd.Get("Idempotency-Key") != a || hd.Get(transport.AttemptHeader) != row.AttemptID || hd.Get(apiKeyHeader) != apiKeyValue ||
		hd.Get("User-Agent") != "agentarium-adapter/receiver-sender" || hd.Get("Traceparent") != "" {
		t.Fatalf("headers %v", hd)
	}

	ops := h.log.list()
	order := []string{"reserve", "claim", "outcome:dispatched", "raise:synthetic", "pending:response_received", "outcome:response_received", "result:accepted", "state:completed"}
	last := -1
	for _, o := range order {
		i := indexOf(ops, o)
		if i <= last {
			t.Fatalf("commit order broken at %s: %v", o, ops)
		}
		last = i
	}
	if got := h.coord.transitions(); !slices.Equal(got, []string{"dispatched", "response_received"}) {
		t.Fatalf("transitions %v", got)
	}
	obs := h.coord.last().Observation
	if obs.LocalAddr == nil || obs.LocalPort == nil || obs.PeerAddrKind == nil || obs.PodUID == nil || obs.SendStartedAt == nil || obs.ResponseAt == nil || obs.WireBodyDigest == nil {
		t.Fatalf("observation incomplete: %+v", obs)
	}
	if *obs.WireBodyDigest != *in.Envelope.ContentDigest {
		t.Fatal("observation wire_body_digest is not the approved digest")
	}
	res := h.store.results[row.AttemptID]
	if res.ExecutionState != "accepted" || res.EvidenceLevel != "accepted" || res.DataClass != "synthetic" || !strings.Contains(string(res.ResultBody), "effect_id") {
		t.Fatalf("result %+v", res)
	}
	if d, _ := canonical.CanonicalDigestJSON(res.ResultBody); d != res.ResultDigest {
		t.Fatal("result_digest is not the canonical digest of result_body")
	}
	if h.store.data[execute.DataStateKey{WorkloadID: "agent-runtime-0"}] != "synthetic" {
		t.Fatalf("data state %v", h.store.data)
	}
	if got := h.audit.types(); !slices.Equal(got, []string{"preflight_passed", "dispatch_started", "response_received"}) {
		t.Fatalf("events %v", got)
	}
	if ev := h.audit.find("response_received"); ev.Payload["status_code"] != 201 || ev.AttemptID != row.AttemptID {
		t.Fatalf("response_received %+v", ev)
	}
	for _, ev := range h.audit.events {
		for k, v := range ev.Payload {
			if s, ok := v.(string); ok && strings.Contains(s, apiKeyValue) {
				t.Fatalf("credential value in audit payload %s", k)
			}
		}
	}
}

// Changes after approval are blocked before anything is reserved or sent.
func TestChangedAfterApprovalIsRejectedBeforeSend(t *testing.T) {
	cases := map[string]struct {
		mut    func(h *harness, in *execute.Inputs)
		code   string
		fields string
	}{
		"body changed": {func(_ *harness, in *execute.Inputs) {
			in.Content.ContentBytes = []byte(`{"email":null,"summary":"30 pods restarted"}`)
		}, "CONTENT_DIGEST_MISMATCH", "content_digest"},
		"target changed": {func(_ *harness, in *execute.Inputs) {
			in.Envelope.CanonicalTarget.TargetID = "receiver-probe"
		}, "PREFLIGHT_MISMATCH", "action_digest"},
		"target changed with recomputed envelope digest": {func(_ *harness, in *execute.Inputs) {
			in.Envelope.CanonicalTarget.TargetID = "receiver-probe"
			in.Envelope.ActionDigest, _ = canonical.ActionDigest(in.Envelope.HashObject())
		}, "PREFLIGHT_MISMATCH", "action_digest"},
		"disclosure widened": {func(_ *harness, in *execute.Inputs) {
			in.Envelope.DisclosureFields = []string{"email", "summary"}
		}, "PREFLIGHT_MISMATCH", "action_digest"},
		"bundle replaced": {func(_ *harness, in *execute.Inputs) {
			in.Decision.PolicyBundleID = "bundle-0"
		}, "PREFLIGHT_MISMATCH", "policy_bundle_id"},
		"catalog changed": {func(_ *harness, in *execute.Inputs) {
			in.Decision.CatalogDigest = strings.Repeat("0", 64)
		}, "CATALOG_DIGEST_MISMATCH", "catalog_digest"},
		"not allow": {func(_ *harness, in *execute.Inputs) {
			in.Decision.Verdict = "approval_required"
		}, "PREFLIGHT_MISMATCH", "verdict"},
		"other adapter": {func(_ *harness, in *execute.Inputs) {
			in.Decision.AdapterID = "model"
		}, "PREFLIGHT_MISMATCH", "adapter_id"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			d, a := h.action(okPayload)
			h.mutate(d, func(in *execute.Inputs) { tc.mut(h, in) })
			row := h.run(d, a)
			if row.State != execute.StatePreflightRejected {
				t.Fatalf("state %s", row.State)
			}
			if h.recv.count.Load() != 0 || h.coord.reservations != 0 || h.broker.calls.Load() != 0 {
				t.Fatalf("sent %d reserved %d broker %d", h.recv.count.Load(), h.coord.reservations, h.broker.calls.Load())
			}
			ev := h.audit.find("preflight_rejected")
			if ev == nil || !slices.Contains(ev.Payload["reason_codes"].([]string), tc.code) || !slices.Contains(ev.Payload["compared_fields"].([]string), tc.fields) {
				t.Fatalf("event %+v", ev)
			}
			if h.audit.find("preflight_passed") != nil {
				t.Fatal("preflight_passed recorded for a rejected execution")
			}
		})
	}
}

func TestBundleDisclosureAllowlist(t *testing.T) {
	h := newHarness(t)
	d, a := h.action(`{"summary":"3 pods restarted","email":"ops@example.com"}`)
	if row := h.run(d, a); row.State != execute.StatePreflightRejected || h.recv.count.Load() != 0 {
		t.Fatalf("email outside data.receiver.allowed_disclosure_fields: state %s", row.State)
	}
}

// The same decision twice and twenty times concurrently: one reservation, one
// send, and the replays answer the current state.
func TestExecuteIdempotent(t *testing.T) {
	h := newHarness(t)
	d, a := h.action(okPayload)
	var wg sync.WaitGroup
	created := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, c, err := h.engine.Submit(context.Background(), d, a)
			if err != nil {
				t.Error(err)
			}
			created <- c
		}()
	}
	wg.Wait()
	h.engine.Wait()
	close(created)
	n := 0
	for c := range created {
		if c {
			n++
		}
	}
	if n != 1 || h.coord.reservations != 1 || h.recv.count.Load() != 1 {
		t.Fatalf("created %d reservations %d sends %d", n, h.coord.reservations, h.recv.count.Load())
	}
	row, c, _ := h.engine.Submit(context.Background(), d, a)
	if c || row.State != execute.StateCompleted {
		t.Fatalf("replay created=%v state %s", c, row.State)
	}
	h.engine.Wait()
	if h.coord.reservations != 1 || h.recv.count.Load() != 1 {
		t.Fatal("replay did new work")
	}
}

func TestCredentialFailureReleases(t *testing.T) {
	h := newHarness(t)
	h.broker.fail = true
	d, a := h.action(okPayload)
	row := h.run(d, a)
	if row.State != execute.StateFailed || h.recv.count.Load() != 0 {
		t.Fatalf("state %s sends %d", row.State, h.recv.count.Load())
	}
	o := h.coord.last()
	if o.Transition != "released" || !slices.Equal(o.ReasonCodes, []string{"CREDENTIAL_UNAVAILABLE"}) || o.Observation != nil {
		t.Fatalf("outcome %+v", o)
	}
	if slices.Contains(h.log.list(), "claim") {
		t.Fatal("permit claimed after a credential failure")
	}
}

func TestPermitRefusedReleases(t *testing.T) {
	h := newHarness(t)
	h.coord.refuseCheck = []string{"HOLD_ACTIVE"}
	d, a := h.action(okPayload)
	row := h.run(d, a)
	if row.State != execute.StateFailed || h.recv.count.Load() != 0 {
		t.Fatalf("state %s sends %d", row.State, h.recv.count.Load())
	}
	if o := h.coord.last(); o.Transition != "released" || !slices.Equal(o.ReasonCodes, []string{"HOLD_ACTIVE"}) {
		t.Fatalf("outcome %+v", o)
	}
}

func TestReservationRefusedEndsFailed(t *testing.T) {
	h := newHarness(t)
	h.coord.refuseRes = []string{"POLICY_EPOCH_STALE"}
	d, a := h.action(okPayload)
	row := h.run(d, a)
	if row.State != execute.StateFailed || h.recv.count.Load() != 0 || h.broker.calls.Load() != 0 {
		t.Fatalf("state %s", row.State)
	}
	if got := h.audit.types(); !slices.Equal(got, []string{"preflight_passed"}) {
		t.Fatalf("events %v (a refused reservation is the coordinator's event)", got)
	}
}

func TestBeforeWroteHeadersFailures(t *testing.T) {
	cases := map[string]struct {
		mut   func(h *harness)
		code  string
		stage string
	}{
		"connect refused": {func(h *harness) { h.recv.srv.Close() }, "TARGET_UNAVAILABLE", "connect"},
		"outside allowed_cidrs": {func(h *harness) {
			h.resolver[receiverHost] = []netip.Addr{netip.MustParseAddr("192.0.2.10")}
		}, "DESTINATION_NOT_ALLOWED", "connect"},
		"dns rebinding mixed answer": {func(h *harness) {
			h.resolver[receiverHost] = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")}
		}, "DESTINATION_NOT_ALLOWED", "connect"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			tc.mut(h)
			d, a := h.action(okPayload)
			row := h.run(d, a)
			if row.State != execute.StateFailed || h.recv.count.Load() != 0 {
				t.Fatalf("state %s sends %d", row.State, h.recv.count.Load())
			}
			if got := h.coord.transitions(); !slices.Equal(got, []string{"failed"}) {
				t.Fatalf("transitions %v", got)
			}
			if o := h.coord.last(); !slices.Equal(o.ReasonCodes, []string{tc.code}) || o.Observation == nil {
				t.Fatalf("outcome %+v", o)
			}
			ev := h.audit.find("attempt_failed")
			if ev == nil || ev.Payload["stage"] != tc.stage {
				t.Fatalf("attempt_failed %+v", ev)
			}
		})
	}
}

// After WroteHeaders the receiver drops the connection: unknown, sent once,
// never re-sent.
func TestNoResponseAfterWroteHeadersIsUnknown(t *testing.T) {
	h := newHarness(t)
	h.recv.respond(func(w http.ResponseWriter, r *http.Request) {
		if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
			c.Close()
		}
	})
	d, a := h.action(okPayload)
	row := h.run(d, a)
	if row.State != execute.StateFailed {
		t.Fatalf("state %s", row.State)
	}
	if got := h.coord.transitions(); !slices.Equal(got, []string{"dispatched", "unknown"}) {
		t.Fatalf("transitions %v", got)
	}
	if h.recv.count.Load() != 1 {
		t.Fatalf("receiver got %d requests, want exactly 1", h.recv.count.Load())
	}
	if h.audit.find("attempt_uncertain") == nil || h.audit.find("dispatch_started") == nil {
		t.Fatalf("events %v", h.audit.types())
	}
	if len(h.store.results) != 0 {
		t.Fatal("action_results written without a response")
	}
}

func TestResponseMappingEndToEnd(t *testing.T) {
	cases := map[int]struct{ state, code, evidence string }{
		409: {"failed", "TARGET_KEY_BODY_CONFLICT", "none"},
		429: {"failed", "TARGET_UNAVAILABLE", "none"},
		400: {"failed", "TARGET_REJECTED", "none"},
		302: {"failed", "TARGET_REJECTED", "none"},
		503: {"unknown", "TARGET_UNAVAILABLE", "unknown"},
		200: {"accepted", "", "accepted"},
	}
	for status, want := range cases {
		h := newHarness(t)
		h.recv.respond(func(w http.ResponseWriter, r *http.Request) {
			if status == 302 {
				w.Header().Set("Location", "https://elsewhere.example/")
			}
			w.WriteHeader(status)
		})
		d, a := h.action(okPayload)
		row := h.run(d, a)
		res := h.store.results[row.AttemptID]
		if row.State != execute.StateCompleted || res.ExecutionState != want.state || res.EvidenceLevel != want.evidence {
			t.Errorf("%d: state %s result %+v", status, row.State, res)
		}
		if string(res.ResultBody) != "null" || res.ResultDigest != canonical.SHA256Hex([]byte("null")) {
			t.Errorf("%d: empty body kept as %s digest %s", status, res.ResultBody, res.ResultDigest)
		}
		o := h.coord.last()
		if o.Transition != "response_received" || (want.code != "" && !slices.Equal(o.ReasonCodes, []string{want.code})) {
			t.Errorf("%d: outcome %+v", status, o)
		}
		if h.recv.count.Load() != 1 {
			t.Errorf("%d: %d sends", status, h.recv.count.Load())
		}
	}
}

func TestOversizeResponse(t *testing.T) {
	h := newHarness(t)
	h.bundle.AdapterConstraints[receiver.AdapterID] = execute.AdapterConstraint{MaxRequestBytes: 65536, MaxResponseBytes: 16, AllowedRouteIDs: []string{"submissions-v1"}}
	d, a := h.action(okPayload)
	row := h.run(d, a)
	res := h.store.results[row.AttemptID]
	if res.ExecutionState != "failed" || string(res.ResultBody) != "null" || !slices.Equal(h.coord.last().ReasonCodes, []string{"RESPONSE_TOO_LARGE"}) {
		t.Fatalf("result %+v outcome %+v", res, h.coord.last())
	}
}

// ② cannot be delivered: the row stays reserved with ① done and the recovery
// record kept; a restart redoes ②–④ without sending again.
func TestOutcomeLostThenRecovered(t *testing.T) {
	h := newHarness(t, withResponseClass("internal"))
	h.coord.mu.Lock()
	h.coord.failOutcome["response_received"] = 100
	h.coord.mu.Unlock()
	d, a := h.action(okPayload)
	row := h.run(d, a)
	if row.State != execute.StateReserved || len(h.store.results) != 0 {
		t.Fatalf("state %s results %d", row.State, len(h.store.results))
	}
	if h.store.data[execute.DataStateKey{WorkloadID: "agent-runtime-0"}] != "internal" {
		t.Fatal("① not applied before ②")
	}
	h.coord.mu.Lock()
	h.coord.failOutcome["response_received"] = 0
	h.coord.mu.Unlock()
	if err := h.engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	row = h.store.row(d)
	if row.State != execute.StateCompleted || len(h.store.results) != 1 || h.recv.count.Load() != 1 {
		t.Fatalf("after restart: state %s results %d sends %d", row.State, len(h.store.results), h.recv.count.Load())
	}
	if got := h.coord.transitions(); !slices.Equal(got, []string{"dispatched", "response_received"}) {
		t.Fatalf("transitions %v", got)
	}
	// A second restart changes nothing.
	if err := h.engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.store.results) != 1 || len(h.coord.transitions()) != 2 {
		t.Fatal("second restart repeated work")
	}
}

// ① cannot be stored: ② is not sent; the sweeper owns the attempt.
func TestRaiseFailureStopsBeforeOutcome(t *testing.T) {
	h := newHarness(t)
	h.store.failSave = true
	d, a := h.action(okPayload)
	row := h.run(d, a)
	if row.State != execute.StateReserved || slices.Contains(h.coord.transitions(), "response_received") {
		t.Fatalf("state %s transitions %v", row.State, h.coord.transitions())
	}
}

// Restart with a reserved row and no recovery record: report unknown with a
// reason code and an observation without a socket. An unclaimed attempt is
// refused (4xx), so the row stays reserved; a claimed one is accepted and
// the execution ends failed.
func TestRestartReservedWithoutRecord(t *testing.T) {
	for _, claimed := range []bool{false, true} {
		h := newHarness(t)
		d, a := h.action(okPayload)
		if _, _, err := h.store.Begin(context.Background(), d, a, receiver.AdapterID); err != nil {
			t.Fatal(err)
		}
		attempt := newUUID()
		h.store.SetState(context.Background(), d, []string{execute.StateReceived}, execute.StateReserved, attempt)
		if claimed {
			h.coord.mu.Lock()
			h.coord.state[attempt] = "claimed"
			h.coord.lastAttempt = attempt
			h.coord.mu.Unlock()
		}
		if err := h.engine.Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		want := execute.StateReserved
		if claimed {
			want = execute.StateFailed
		}
		if row := h.store.row(d); row.State != want || h.recv.count.Load() != 0 {
			t.Fatalf("claimed=%v: state %s sends %d", claimed, row.State, h.recv.count.Load())
		}
		p, err := h.store.Pending(context.Background(), d)
		if err != nil || p.Transition != "unknown" || !slices.Equal(p.ReasonCodes, []string{"STATE_STORE_UNAVAILABLE"}) ||
			p.Observation.LocalAddr != nil || p.Observation.NetnsInode != nil || p.Observation.PodUID == nil {
			t.Fatalf("recovery record %+v %v", p, err)
		}
		if claimed && !slices.Equal(h.coord.transitions(), []string{"unknown"}) {
			t.Fatalf("transitions %v", h.coord.transitions())
		}
	}
}

// A definitive refusal (409 or 422) of the outcome stops before ③ and ④: no
// action_results row, the execution stays reserved. The next restart
// reports the same outcome; a 2xx then completes it with one result.
func TestOutcomeRefusedStaysReservedUntilAccepted(t *testing.T) {
	for _, status := range []int{409, 422} {
		h := newHarness(t)
		h.coord.mu.Lock()
		h.coord.refuseOutcome["response_received"] = 1
		h.coord.refuseCode = status
		h.coord.mu.Unlock()
		d, a := h.action(okPayload)
		row := h.run(d, a)
		if row.State != execute.StateReserved || len(h.store.results) != 0 || h.audit.find("response_received") != nil {
			t.Fatalf("%d: state %s results %d events %v", status, row.State, len(h.store.results), h.audit.types())
		}
		if err := h.engine.Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		row = h.store.row(d)
		if row.State != execute.StateCompleted || len(h.store.results) != 1 || h.recv.count.Load() != 1 {
			t.Fatalf("%d after restart: state %s results %d sends %d", status, row.State, len(h.store.results), h.recv.count.Load())
		}
		if got := h.coord.transitions(); !slices.Equal(got, []string{"dispatched", "response_received"}) {
			t.Fatalf("%d: transitions %v", status, got)
		}
	}
}

// Crash after the audit append and before ③: the replay re-reports the same
// outcome (2xx for an identical report) and re-sends the event with the same
// event_id and body, so TASK-07 deduplicates it.
func TestReplayKeepsEventID(t *testing.T) {
	h := newHarness(t)
	h.store.mu.Lock()
	h.store.failResult = 1
	h.store.mu.Unlock()
	d, a := h.action(okPayload)
	if row := h.run(d, a); row.State != execute.StateReserved || len(h.store.results) != 0 {
		t.Fatalf("state %s results %d", row.State, len(h.store.results))
	}
	if err := h.engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if row := h.store.row(d); row.State != execute.StateCompleted || len(h.store.results) != 1 || h.recv.count.Load() != 1 {
		t.Fatalf("state %s results %d sends %d", row.State, len(h.store.results), h.recv.count.Load())
	}
	var sent []execute.Event
	for _, ev := range h.audit.events {
		if ev.Type == "response_received" {
			sent = append(sent, ev)
		}
	}
	if len(sent) != 2 || sent[0].EventID == "" || sent[0].EventID != sent[1].EventID {
		t.Fatalf("response_received events %+v", sent)
	}
	b0, _ := json.Marshal(sent[0])
	b1, _ := json.Marshal(sent[1])
	if string(b0) != string(b1) {
		t.Fatalf("replayed event body differs:\n%s\n%s", b0, b1)
	}
	ids := map[string]bool{}
	for _, ev := range h.audit.events {
		if ev.EventID == "" {
			t.Fatalf("%s without event_id", ev.Type)
		}
		ids[ev.EventID] = true
	}
	if len(ids) != len(h.audit.events)-1 {
		t.Fatalf("only the replayed event may repeat an event_id: %d ids for %d events", len(ids), len(h.audit.events))
	}
}

// Restart with a received row processes it from the beginning.
func TestRestartReceivedIsProcessed(t *testing.T) {
	h := newHarness(t)
	d, a := h.action(okPayload)
	if _, _, err := h.store.Begin(context.Background(), d, a, receiver.AdapterID); err != nil {
		t.Fatal(err)
	}
	if err := h.engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if row := h.store.row(d); row.State != execute.StateCompleted || h.recv.count.Load() != 1 {
		t.Fatalf("state %s sends %d", row.State, h.recv.count.Load())
	}
}

func TestMapResponseTable(t *testing.T) {
	ad := receiver.Adapter{}
	for _, tc := range []struct {
		r                     transport.Result
		state, code, evidence string
	}{
		{transport.Result{Responded: true, StatusCode: 201}, "accepted", "", "accepted"},
		{transport.Result{Responded: true, StatusCode: 200}, "accepted", "", "accepted"},
		{transport.Result{Responded: true, StatusCode: 201, Oversize: true}, "failed", "RESPONSE_TOO_LARGE", "none"},
		{transport.Result{Responded: true, StatusCode: 301}, "failed", "TARGET_REJECTED", "none"},
		{transport.Result{Responded: true, StatusCode: 409}, "failed", "TARGET_KEY_BODY_CONFLICT", "none"},
		{transport.Result{Responded: true, StatusCode: 422}, "failed", "TARGET_REJECTED", "none"},
		{transport.Result{Responded: true, StatusCode: 429}, "failed", "TARGET_UNAVAILABLE", "none"},
		{transport.Result{Responded: true, StatusCode: 500}, "unknown", "TARGET_UNAVAILABLE", "unknown"},
		{transport.Result{Responded: true, StatusCode: 504}, "unknown", "TARGET_UNAVAILABLE", "unknown"},
	} {
		m := ad.MapResponse(tc.r)
		if m.ExecutionState != tc.state || m.EvidenceLevel != tc.evidence || (tc.code == "" && len(m.ReasonCodes) != 0) || (tc.code != "" && !slices.Equal(m.ReasonCodes, []string{tc.code})) {
			t.Errorf("%d oversize=%v: %+v", tc.r.StatusCode, tc.r.Oversize, m)
		}
	}
}

func (a *auditor) all(typ string) []execute.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []execute.Event
	for _, e := range a.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// The attempt event cannot be recorded: ③ and ④ wait. The restart re-sends
// the stored event_id once and completes.
func TestAuditFailureKeepsReserved(t *testing.T) {
	h := newHarness(t)
	h.audit.mu.Lock()
	h.audit.fail["response_received"] = 1
	h.audit.mu.Unlock()
	d, a := h.action(okPayload)
	if row := h.run(d, a); row.State != execute.StateReserved || len(h.store.results) != 0 {
		t.Fatalf("state %s results %d", row.State, len(h.store.results))
	}
	p, err := h.store.Pending(context.Background(), d)
	if err != nil || p.Event == nil {
		t.Fatalf("recovery record %v", err)
	}
	if err := h.engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if row := h.store.row(d); row.State != execute.StateCompleted || len(h.store.results) != 1 || h.recv.count.Load() != 1 {
		t.Fatalf("state %s results %d sends %d", row.State, len(h.store.results), h.recv.count.Load())
	}
	got := h.audit.all("response_received")
	if len(got) != 1 || got[0].EventID != p.Event.EventID {
		t.Fatalf("recorded %+v, stored id %s", got, p.Event.EventID)
	}
}

// Crash after the preflight_passed audit append and before the reservation:
// the received row is processed again on restart and preflight_passed goes
// out with the same event_id and body.
func TestPreflightPassedReplayKeepsEventID(t *testing.T) {
	h := newHarness(t)
	h.audit.mu.Lock()
	h.audit.lostAck["preflight_passed"] = 1
	h.audit.mu.Unlock()
	d, a := h.action(okPayload)
	if row := h.run(d, a); row.State != execute.StateReceived || h.coord.reservations != 0 {
		t.Fatalf("state %s reservations %d", row.State, h.coord.reservations)
	}
	if err := h.engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if row := h.store.row(d); row.State != execute.StateCompleted || h.coord.reservations != 1 || h.recv.count.Load() != 1 {
		t.Fatalf("state %s reservations %d sends %d", row.State, h.coord.reservations, h.recv.count.Load())
	}
	got := h.audit.all("preflight_passed")
	if len(got) != 2 || got[0].EventID == "" || got[0].EventID != got[1].EventID {
		t.Fatalf("preflight_passed events %+v", got)
	}
	b0, _ := json.Marshal(got[0])
	b1, _ := json.Marshal(got[1])
	if string(b0) != string(b1) {
		t.Fatalf("bodies differ:\n%s\n%s", b0, b1)
	}
}

// preflight_rejected is recorded before the state moves; an audit failure
// keeps the row received and the restart re-sends the same event_id.
func TestPreflightRejectedReplayKeepsEventID(t *testing.T) {
	h := newHarness(t)
	h.audit.mu.Lock()
	h.audit.lostAck["preflight_rejected"] = 1
	h.audit.mu.Unlock()
	d, a := h.action(okPayload)
	h.mutate(d, func(in *execute.Inputs) { in.Decision.Verdict = "deny" })
	if row := h.run(d, a); row.State != execute.StateReceived {
		t.Fatalf("state %s", row.State)
	}
	if err := h.engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if row := h.store.row(d); row.State != execute.StatePreflightRejected || h.recv.count.Load() != 0 {
		t.Fatalf("state %s", row.State)
	}
	got := h.audit.all("preflight_rejected")
	if len(got) != 2 || got[0].EventID != got[1].EventID {
		t.Fatalf("preflight_rejected events %+v", got)
	}
}
