package export

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	fx "github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/testfixture"
)

// A restarted exporter has no memory of its holds. It must reload only the
// export_lag holds owned by audit-export and still release them only after a
// passing probe; other components' and security holds are never touched.
func TestOwnedHoldRecovery(t *testing.T) {
	ctx := context.Background()
	pki := fx.NewPKI(t, t.TempDir())
	cert, _, _ := pki.Issue(t, "exporter", fx.ExporterSAN, false, x509.ExtKeyUsageClientAuth)
	health := fx.NewControlHealth(t, pki)
	node := "6a6f2b8e-34c1-4d55-8a0c-0b6f0f2f7a10"
	own := []string{health.SeedHold("global", "*", "export_lag", "audit-export"), health.SeedHold("node", node, "export_lag", "audit-export")}
	foreign := []string{health.SeedHold("global", "*", "db_unavailable", "audit-db"), health.SeedHold("global", "*", "audit_integrity", "control-health")}
	client := pki.ServiceClient(t, cert, fx.ControlHealthSAN)
	objects := &probeObjects{fail: true, data: map[string][]byte{}}
	r := &HealthReporter{Client: client, URL: health.URL, Prober: &ExportProber{Objects: objects, Bucket: "audit-evidence"}}

	t.Run("listing is owner-only", func(t *testing.T) {
		for _, q := range []string{"?owner_component=audit-db", "?owner_component=control-health", ""} {
			resp, err := client.Get(health.URL + "/internal/holds" + q)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("listing %q allowed for audit-exporter", q)
			}
		}
	})
	t.Run("unavailable control-health retries with backoff and releases nothing", func(t *testing.T) {
		health.FailListings(3)
		loopCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		var mu sync.Mutex
		var failures []time.Time
		go r.RecoverLoop(loopCtx, 20*time.Millisecond, 200*time.Millisecond, func(err error) {
			if !errors.Is(err, ErrHoldListing) {
				t.Errorf("unexpected recovery error: %v", err)
			}
			mu.Lock()
			failures = append(failures, time.Now())
			mu.Unlock()
		})
		fx.Eventually(t, 5*time.Second, "recovered holds", func() bool { return r.HeldScopes() == 2 })
		mu.Lock()
		defer mu.Unlock()
		// Delays 20ms then 40ms: the third failure comes at least 60ms after the first.
		if health.ListCalls() < 4 || len(failures) != 3 || failures[2].Sub(failures[0]) < 55*time.Millisecond {
			t.Fatalf("no growing backoff: calls=%d failures=%v", health.ListCalls(), failures)
		}
		for _, id := range append(own, foreign...) {
			if health.ReleaseCalls(id) != 0 {
				t.Fatal("release attempted during recovery")
			}
		}
	})
	t.Run("recovered hold with failing probe stays held", func(t *testing.T) {
		if err := r.releaseRecovered(ctx, map[holdScope]bool{}); err == nil || r.HeldScopes() != 2 {
			t.Fatalf("failed probe released: %v held=%d", err, r.HeldScopes())
		}
		for _, id := range own {
			if h, _ := health.HoldByID(id); h.ReleasedAt != nil {
				t.Fatal("hold released after failing probe")
			}
		}
	})
	t.Run("passing probe releases only owned holds", func(t *testing.T) {
		objects.fail = false
		if err := r.releaseRecovered(ctx, map[holdScope]bool{}); err != nil || r.HeldScopes() != 0 {
			t.Fatalf("release: %v held=%d", err, r.HeldScopes())
		}
		for _, id := range own {
			if h, _ := health.HoldByID(id); h.ReleasedAt == nil || h.ReleaseRef == "" {
				t.Fatalf("owned hold not released: %+v", h)
			}
		}
		for _, id := range foreign {
			if h, _ := health.HoldByID(id); h.ReleasedAt != nil || health.ReleaseCalls(id) != 0 {
				t.Fatalf("foreign hold touched: %+v", h)
			}
		}
		// A later recovery request finds nothing left to release.
		r.RequestRecovery()
		time.Sleep(100 * time.Millisecond)
		if r.HeldScopes() != 0 {
			t.Fatal("released hold recovered again")
		}
	})
}

// Every replica recovers the same holds. When replica A releases one, replica
// B's release gets 409 (#159); B forgets it and its next listing, which
// replaces the remembered set, does not bring it back.
func TestRecoveredHoldReleasedByAnotherReplica(t *testing.T) {
	ctx := context.Background()
	pki := fx.NewPKI(t, t.TempDir())
	cert, _, _ := pki.Issue(t, "exporter", fx.ExporterSAN, false, x509.ExtKeyUsageClientAuth)
	health := fx.NewControlHealth(t, pki)
	id := health.SeedHold("global", "*", "export_lag", "audit-export")
	client := pki.ServiceClient(t, cert, fx.ControlHealthSAN)
	objects := &probeObjects{data: map[string][]byte{}}
	a := &HealthReporter{Client: client, URL: health.URL, Prober: &ExportProber{Objects: objects, Bucket: "audit-evidence"}}
	b := &HealthReporter{Client: client, URL: health.URL, Prober: &ExportProber{Objects: objects, Bucket: "audit-evidence"}}
	for _, r := range []*HealthReporter{a, b} {
		if n, err := r.RecoverHolds(ctx); err != nil || n != 1 {
			t.Fatalf("recover: %d %v", n, err)
		}
	}
	b.mu.Lock()
	b.held[holdScope{"node", "6a6f2b8e-34c1-4d55-8a0c-0b6f0f2f7a10"}] = "11111111-2222-4333-8444-555555555555" // stale entry
	b.mu.Unlock()
	if err := a.releaseRecovered(ctx, map[holdScope]bool{}); err != nil {
		t.Fatal(err)
	}
	if err := b.releaseRecovered(ctx, map[holdScope]bool{}); err != nil || b.HeldScopes() != 0 {
		t.Fatalf("replica B kept a released or unknown hold: %v held=%d", err, b.HeldScopes())
	}
	if n, err := b.RecoverHolds(ctx); err != nil || n != 0 || b.HeldScopes() != 0 {
		t.Fatalf("listing brought back a released hold: %d %v", n, err)
	}
	if calls := health.ReleaseCalls(id); calls != 2 {
		t.Fatalf("release calls %d", calls)
	}
}

// A 409 on a hold that the owned listing still shows open is insufficient
// evidence: it stays an error and the hold is kept for the next round.
func TestConflictOnOpenHoldStaysAnError(t *testing.T) {
	ctx := context.Background()
	pki := fx.NewPKI(t, t.TempDir())
	cert, _, _ := pki.Issue(t, "exporter", fx.ExporterSAN, false, x509.ExtKeyUsageClientAuth)
	health := fx.NewControlHealth(t, pki)
	id := health.SeedHold("global", "*", "export_lag", "audit-export")
	health.RefuseEvidence(id, true)
	var logged []error
	r := &HealthReporter{Client: pki.ServiceClient(t, cert, fx.ControlHealthSAN), URL: health.URL,
		Prober: &ExportProber{Objects: &probeObjects{data: map[string][]byte{}}, Bucket: "audit-evidence"}, OnReleaseError: func(e error) { logged = append(logged, e) }}
	if _, err := r.RecoverHolds(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.releaseRecovered(ctx, map[holdScope]bool{}); !errors.Is(err, errHoldConflict) || r.HeldScopes() != 1 || len(logged) != 0 {
		t.Fatalf("insufficient evidence treated as released: %v held=%d logged=%v", err, r.HeldScopes(), logged)
	}
	health.RefuseEvidence(id, false)
	if err := r.releaseRecovered(ctx, map[holdScope]bool{}); err != nil || r.HeldScopes() != 0 {
		t.Fatalf("release after evidence accepted: %v held=%d", err, r.HeldScopes())
	}
	if h, _ := health.HoldByID(id); h.ReleasedAt == nil {
		t.Fatal("hold not released")
	}
}

// Recovering H2 while completing a stale H1 release must retain H2 for a
// later probe/release round, even though both holds have the same scope.
func TestStaleReleasePreservesReplacementHold(t *testing.T) {
	ctx := context.Background()
	pki := fx.NewPKI(t, t.TempDir())
	cert, _, _ := pki.Issue(t, "exporter", fx.ExporterSAN, false, x509.ExtKeyUsageClientAuth)
	health := fx.NewControlHealth(t, pki)
	health.SeedHold("global", "*", "export_lag", "audit-export")
	client := pki.ServiceClient(t, cert, fx.ControlHealthSAN)
	newReporter := func() *HealthReporter {
		return &HealthReporter{Client: client, URL: health.URL, Prober: &ExportProber{Objects: &probeObjects{data: map[string][]byte{}}, Bucket: "audit-evidence"}}
	}
	a, b := newReporter(), newReporter()
	for _, r := range []*HealthReporter{a, b} {
		if _, err := r.RecoverHolds(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.releaseRecovered(ctx, map[holdScope]bool{}); err != nil {
		t.Fatal(err)
	}
	replacement := health.SeedHold("global", "*", "export_lag", "audit-export")
	if err := b.releaseRecovered(ctx, map[holdScope]bool{}); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	got := b.held[holdScope{"global", "*"}]
	b.mu.Unlock()
	if got != replacement {
		t.Fatalf("replacement hold forgotten: got %q want %q", got, replacement)
	}
	if health.ReleaseCalls(replacement) != 0 {
		t.Fatal("replacement released using stale hold evidence")
	}
	if err := b.releaseRecovered(ctx, map[holdScope]bool{}); err != nil {
		t.Fatal(err)
	}
	if h, _ := health.HoldByID(replacement); h.ReleasedAt == nil {
		t.Fatal("replacement hold not released in later round")
	}
}
