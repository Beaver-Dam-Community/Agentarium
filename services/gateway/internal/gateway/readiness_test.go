package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/Beaver-Dam-Community/Agentarium/packages/healthlease"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

// readinessServer answers GET /internal/control-health/work-readiness/checks/{id}
// with status and body, and records the forwarded peer identity.
func readinessServer(t *testing.T, status int, body any, peer *string, session string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if peer != nil {
			*peer = r.Header.Get(PeerIdentityHeader)
		}
		if r.Header.Get("X-Agentarium-Peer-Session") != session {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func errCode(err error) (int, string) {
	var e *Error
	if errors.As(err, &e) {
		return e.Status, e.Code
	}
	if err == nil {
		return 0, ""
	}
	return -1, err.Error()
}

func TestHTTPReadiness(t *testing.T) {
	c := userCaller()
	ref := ReadinessRef{WorkRunID: uuid.NewString(), CheckID: uuid.NewString()}
	ms := int64(1500)
	zero := int64(0)
	ready := func() readinessCheck {
		return readinessCheck{CheckID: ref.CheckID, WorkRunID: ref.WorkRunID, SessionID: c.SessionID, WorkloadID: c.WorkloadID,
			CallerIdentity: c.SAN, State: "ready", ReasonCodes: []string{}, RemainingValidMS: &ms}
	}
	with := func(f func(*readinessCheck)) readinessCheck { r := ready(); f(&r); return r }
	cases := []struct {
		name   string
		status int
		body   any
		want   int
		code   string
	}{
		{"ready", 200, ready(), 0, ""},
		{"other check", 200, with(func(r *readinessCheck) { r.CheckID = uuid.NewString() }), 403, "WORK_READINESS_BINDING_MISMATCH"},
		{"other run", 200, with(func(r *readinessCheck) { r.WorkRunID = uuid.NewString() }), 403, "WORK_READINESS_BINDING_MISMATCH"},
		{"other session", 200, with(func(r *readinessCheck) { r.SessionID = uuid.NewString() }), 403, "WORK_READINESS_BINDING_MISMATCH"},
		{"other workload", 200, with(func(r *readinessCheck) { r.WorkloadID = "agent-exec/other" }), 403, "WORK_READINESS_BINDING_MISMATCH"},
		{"other caller", 200, with(func(r *readinessCheck) { r.CallerIdentity = c.SAN + "x" }), 403, "WORK_READINESS_BINDING_MISMATCH"},
		{"pending", 200, with(func(r *readinessCheck) { r.State = "pending" }), 503, "WORK_READINESS_EXPIRED"},
		{"blocked worker", 200, with(func(r *readinessCheck) {
			r.State, r.ReasonCodes = "blocked", []string{"WORKER_OBSERVATION_NOT_READY"}
		}), 503, "WORKER_OBSERVATION_NOT_READY"},
		{"blocked binding", 200, with(func(r *readinessCheck) {
			r.State, r.ReasonCodes = "blocked", []string{"WORK_READINESS_BINDING_MISMATCH"}
		}), 403, "WORK_READINESS_BINDING_MISMATCH"},
		{"blocked budget", 200, with(func(r *readinessCheck) {
			r.State, r.ReasonCodes = "blocked", []string{"SESSION_BUDGET_EXHAUSTED"}
		}), 503, "WORK_READINESS_EXPIRED"},
		{"no remaining", 200, with(func(r *readinessCheck) { r.RemainingValidMS = &zero }), 503, "WORK_READINESS_EXPIRED"},
		{"remaining missing", 200, with(func(r *readinessCheck) { r.RemainingValidMS = nil }), 503, "WORK_READINESS_EXPIRED"},
		// control-health on main has no work-readiness route: plain 404.
		{"unknown route or check", 404, nil, 503, "WORK_READINESS_EXPIRED"},
		{"forbidden", 403, nil, 403, "WORK_READINESS_BINDING_MISMATCH"},
		{"unavailable", 503, nil, 503, "CONTROL_HEALTH_UNAVAILABLE"},
		{"invalid body", 200, "not a check", 503, "CONTROL_HEALTH_UNAVAILABLE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var peer string
			srv := readinessServer(t, tc.status, tc.body, &peer, c.SessionID)
			err := HTTPReadiness{BaseURL: srv.URL, Client: srv.Client()}.Check(context.Background(), c, ref)
			if st, code := errCode(err); st != tc.want || code != tc.code {
				t.Fatalf("got %d %s, want %d %s", st, code, tc.want, tc.code)
			}
			if peer != c.SAN {
				t.Fatalf("peer identity %q", peer)
			}
		})
	}
	// A reference that is not a pair of canonical UUIDs never reaches
	// control-health; an unconfigured client is not ready.
	srv := readinessServer(t, 200, ready(), nil, c.SessionID)
	h := HTTPReadiness{BaseURL: srv.URL, Client: srv.Client()}
	if st, code := errCode(h.Check(context.Background(), c, ReadinessRef{WorkRunID: "run-1", CheckID: ref.CheckID})); st != 503 || code != "WORK_READINESS_EXPIRED" {
		t.Fatalf("non-UUID ref: %d %s", st, code)
	}
	if err := (HTTPReadiness{}).Check(context.Background(), c, ref); !errors.Is(err, ErrUnwired) {
		t.Fatalf("unconfigured: %v", err)
	}
	srv.Close()
	if st, code := errCode(h.Check(context.Background(), c, ref)); st != 503 || code != "CONTROL_HEALTH_UNAVAILABLE" {
		t.Fatalf("unreachable: %d %s", st, code)
	}
}

type fakeBundleStatus struct {
	snap *policyloader.Snapshot
	st   policyloader.Status
}

func (f fakeBundleStatus) Current() *policyloader.Snapshot { return f.snap }
func (f fakeBundleStatus) Status() policyloader.Status     { return f.st }

func TestLeaseState(t *testing.T) {
	p := loadTestPolicy(t, "")
	ok := func(context.Context) error { return nil }
	down := func(context.Context) error { return errors.New("down") }
	st := LeaseState(p.loader, ok)(context.Background())
	if st.ObservedState != healthlease.Healthy || st.ActiveVersion == nil || *st.ActiveVersion != p.artifact ||
		st.LoadedArtifactDigest == nil || *st.LoadedArtifactDigest != p.artifact ||
		st.ActiveBundleRevision == nil || *st.ActiveBundleRevision != testRev || st.CanonicalVersion == nil || *st.CanonicalVersion != "v1" {
		t.Fatalf("loaded: %+v", st)
	}
	if st := LeaseState(p.loader, down)(context.Background()); st.ObservedState != healthlease.Degraded || *st.ActiveVersion != p.artifact {
		t.Fatalf("database down: %+v", st)
	}
	if st := LeaseState(fakeBundleStatus{}, ok)(context.Background()); st.ObservedState != healthlease.Degraded || st.ActiveVersion != nil {
		t.Fatalf("no bundle: %+v", st)
	}
	failed := fakeBundleStatus{snap: p.loader.Current(), st: policyloader.Status{LastError: "signature"}}
	if st := LeaseState(failed, ok)(context.Background()); st.ObservedState != healthlease.Degraded || *st.ActiveVersion != p.artifact {
		t.Fatalf("failed reload keeps the previous digest, degraded: %+v", st)
	}
}
