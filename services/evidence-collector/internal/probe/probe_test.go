package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/receipt"
)

const probeKey = "5a2b8a0e-6c0b-4b8e-9d0e-7b0c1f2a3b4c"

type fakeReader struct {
	mu   sync.Mutex
	fail bool
}

func (f *fakeReader) Read(_ context.Context, id string) (*receipt.Receipt, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, "", errors.New("receipt API down")
	}
	return &receipt.Receipt{ActionKey: id, TargetIdentity: "receiver-primary"}, strings.Repeat("b", 64), nil
}

// fakeHealth records the control-health calls.
type fakeHealth struct {
	mu       sync.Mutex
	reports  []map[string]any
	holds    []map[string]any
	releases []map[string]any
	owned    []map[string]any
	nextID   int
}

func (h *fakeHealth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var body map[string]any
	if r.Method == http.MethodPost {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			w.WriteHeader(422)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/internal/holds":
		if r.URL.Query().Get("owner_component") != Component {
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"holds": h.owned})
	case r.URL.Path == "/internal/control-health/probe-results":
		h.nextID++
		h.reports = append(h.reports, body)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"probe_result_id": fmt.Sprintf("pr-%d", h.nextID)})
	case r.URL.Path == "/internal/holds":
		h.holds = append(h.holds, body)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"hold_id": "hold-1", "decision": "held", "reason_codes": []string{}})
	case strings.HasPrefix(r.URL.Path, "/internal/holds/") && strings.HasSuffix(r.URL.Path, "/release"):
		h.releases = append(h.releases, body)
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/internal/holds/"), "/release")
		_ = json.NewEncoder(w).Encode(map[string]any{"hold_id": id, "released_at": "2026-10-18T00:00:00Z", "release_ref": "x"})
	default:
		w.WriteHeader(404)
	}
}

func newProber(t *testing.T, h *fakeHealth, rd *fakeReader) *Prober {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Prober{Receipts: rd, ProbeActionKey: probeKey, TargetID: "receiver-primary", HealthURL: srv.URL, Client: srv.Client()}
}

func TestThreeFailuresHoldTwoPassesRelease(t *testing.T) {
	h, rd := &fakeHealth{}, &fakeReader{fail: true}
	p := newProber(t, h, rd)
	ctx := context.Background()
	for i := 1; i <= 2; i++ {
		if err := p.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if p.Unhealthy() || len(h.holds) != 0 {
			t.Fatalf("after %d failures: unhealthy=%v holds=%d", i, p.Unhealthy(), len(h.holds))
		}
	}
	if err := p.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if !p.Unhealthy() || len(h.holds) != 1 || p.HoldID() != "hold-1" {
		t.Fatalf("third failure: unhealthy=%v holds=%v", p.Unhealthy(), h.holds)
	}
	hold := h.holds[0]
	if hold["scope"] != "target" || hold["scope_id"] != "receiver-primary" || hold["reason"] != "probe_failed" || len(hold) != 4 {
		t.Fatalf("hold request %v", hold)
	}
	// A fourth failure does not request a second hold.
	if err := p.Once(ctx); err != nil || len(h.holds) != 1 {
		t.Fatal("duplicate hold", err, len(h.holds))
	}
	rd.fail = false
	if err := p.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if p.Unhealthy() || len(h.releases) != 0 {
		t.Fatal("one pass released the hold or kept unhealthy")
	}
	if err := p.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if len(h.releases) != 1 || p.HoldID() != "" {
		t.Fatalf("two passes: releases %v", h.releases)
	}
	ids := h.releases[0]["probe_result_ids"].([]any)
	if len(ids) != 2 || ids[0] != "pr-5" || ids[1] != "pr-6" {
		t.Fatalf("release cites %v, want the two consecutive pass results", ids)
	}
	for i, r := range h.reports {
		if r["probe_kind"] != "receipt" || r["scope"] != "target" || r["scope_id"] != "receiver-primary" {
			t.Fatalf("report %d %v", i, r)
		}
		refs := r["evidence_refs"].([]any)
		if (r["outcome"] == "pass") != (len(refs) == 1) {
			t.Fatalf("report %d refs %v", i, refs)
		}
	}
}

func TestFailureBetweenPassesRestartsCount(t *testing.T) {
	h, rd := &fakeHealth{owned: []map[string]any{{"hold_id": "hold-9", "scope": "target", "scope_id": "receiver-primary", "reason": "probe_failed"}}}, &fakeReader{}
	p := newProber(t, h, rd)
	ctx := context.Background()
	// The owned hold is found again after a restart.
	if err := p.Once(ctx); err != nil || p.HoldID() != "hold-9" {
		t.Fatal("owned hold not resynced", err, p.HoldID())
	}
	rd.fail = true
	_ = p.Once(ctx)
	rd.fail = false
	_ = p.Once(ctx)
	if len(h.releases) != 0 {
		t.Fatal("non-consecutive passes released the hold")
	}
	_ = p.Once(ctx)
	if len(h.releases) != 1 {
		t.Fatal("two consecutive passes did not release")
	}
}

func TestOtherTargetReceiptFails(t *testing.T) {
	h := &fakeHealth{}
	p := newProber(t, h, &fakeReader{})
	p.TargetID = "receiver-other"
	if err := p.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.reports[0]["outcome"] != "fail" {
		t.Fatal("receipt of another target counted as pass")
	}
}
