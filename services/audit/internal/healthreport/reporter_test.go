package healthreport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLeaseReport(t *testing.T) {
	for _, healthy := range []bool{true, false} {
		t.Run(map[bool]string{true: "commit_ok", false: "commit_failed"}[healthy], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/internal/control-health/leases" || r.Method != "POST" {
					t.Error("wrong endpoint")
				}
				var l Lease
				if json.NewDecoder(r.Body).Decode(&l) != nil {
					t.Error("invalid body")
				}
				want := "healthy"
				if !healthy {
					want = "unhealthy"
				}
				if l.Component != "audit-db" || l.Scope != "global" || l.ScopeID != "*" || l.ObservedState != want || l.LeaseUntil.Sub(l.ReportedAt) != 15*time.Second {
					t.Errorf("%+v", l)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"lease_until": l.LeaseUntil, "scope_state": "unhealthy"})
			}))
			defer srv.Close()
			r := Reporter{URL: srv.URL, SourceID: "audit-1", Version: "test", Client: srv.Client(), Check: func(context.Context) error {
				if !healthy {
					return errors.New("commit failed")
				}
				return nil
			}}
			if err := r.Report(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
