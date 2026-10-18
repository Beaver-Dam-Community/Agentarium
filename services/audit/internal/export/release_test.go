package export

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	fx "github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/testfixture"
)

type probeObjects struct {
	fail    bool
	data    map[string][]byte
	creates int
}

func (p *probeObjects) CreateFixed(_ context.Context, key, _ string, data []byte) (int64, error) {
	p.creates++
	if p.fail {
		return 0, errors.New("storage unavailable")
	}
	p.data[key] = data
	return 7, nil
}
func (p *probeObjects) Read(_ context.Context, key string, gen int64) ([]byte, error) {
	if gen != 7 {
		return nil, errors.New("generation")
	}
	return p.data[key], nil
}

// Release follows TASK-07 3.2.1 against the control-health contract fake: no
// release while the scope is pressured or the probe fails (the failed probe is
// still reported), then one release with the server-built release_ref.
func TestHoldReleaseRequiresPassingProbe(t *testing.T) {
	ctx := context.Background()
	pki := fx.NewPKI(t, t.TempDir())
	cert, _, _ := pki.Issue(t, "exporter", fx.ExporterSAN, false, x509.ExtKeyUsageClientAuth)
	health := fx.NewControlHealth(t, pki)
	objects := &probeObjects{fail: true, data: map[string][]byte{}}
	r := &HealthReporter{Client: pki.ServiceClient(t, cert, fx.ControlHealthSAN), URL: health.URL, Prober: &ExportProber{Objects: objects, Bucket: "audit-evidence"}}
	global, node := holdScope{"global", "*"}, holdScope{"node", "6a6f2b8e-34c1-4d55-8a0c-0b6f0f2f7a10"}
	for _, s := range []holdScope{global, node} {
		if err := r.requestHold(ctx, s, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.releaseRecovered(ctx, map[holdScope]bool{global: true, node: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, probes := health.Snapshot(); len(probes) != 0 {
		t.Fatal("pressured scope probed")
	}
	if err := r.releaseRecovered(ctx, map[holdScope]bool{node: true}); err == nil || r.HeldScopes() != 2 {
		t.Fatal("failed probe released or was not reported as an error")
	}
	_, holds, probes := health.Snapshot()
	if len(probes) != 1 || probes[0].Outcome != "fail" || probes[0].Scope != "global" || len(probes[0].EvidenceRefs) != 0 {
		t.Fatalf("failed probe not reported: %+v", probes)
	}
	for _, h := range holds {
		if h.ReleasedAt != nil {
			t.Fatal("hold released after failed probe")
		}
	}
	objects.fail = false
	if err := r.releaseRecovered(ctx, map[holdScope]bool{}); err != nil || r.HeldScopes() != 0 {
		t.Fatalf("release: %v held=%d", err, r.HeldScopes())
	}
	_, holds, probes = health.Snapshot()
	for _, h := range holds {
		if h.ReleasedAt == nil || !strings.HasPrefix(h.ReleaseRef, "auto:audit-export:") {
			t.Fatalf("hold %+v", h)
		}
	}
	for _, p := range probes {
		if p.Outcome == "pass" && p.Scope == "node" && p.NodeUID != node.ID {
			t.Fatalf("node probe without node_uid: %+v", p)
		}
	}
	// Heartbeat-only release (no probe_result_ids) is refused by the contract.
	before := health.Rejected
	if err := r.requestHold(ctx, global, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.post(ctx, "/internal/holds/"+r.held[global]+"/release", map[string]any{"justification": "heartbeat", "evidence_refs": []string{}}, &struct{}{}); err == nil || health.Rejected != before+1 {
		t.Fatalf("heartbeat-only release accepted: %v", err)
	}
}

// Two recovered scopes share one probe per release round, and a hold another
// replica already released (409 per #159) is forgotten instead of retried.
func TestReleaseProbesOncePerRoundAndForgetsReleasedHold(t *testing.T) {
	ctx := context.Background()
	pki := fx.NewPKI(t, t.TempDir())
	cert, _, _ := pki.Issue(t, "exporter", fx.ExporterSAN, false, x509.ExtKeyUsageClientAuth)
	health := fx.NewControlHealth(t, pki)
	objects := &probeObjects{data: map[string][]byte{}}
	client := pki.ServiceClient(t, cert, fx.ControlHealthSAN)
	a := &HealthReporter{Client: client, URL: health.URL, Prober: &ExportProber{Objects: objects, Bucket: "audit-evidence"}}
	b := &HealthReporter{Client: client, URL: health.URL, Prober: &ExportProber{Objects: objects, Bucket: "audit-evidence"}}
	global, node := holdScope{"global", "*"}, holdScope{"node", "6a6f2b8e-34c1-4d55-8a0c-0b6f0f2f7a10"}
	for _, r := range []*HealthReporter{a, b} {
		for _, s := range []holdScope{global, node} {
			if err := r.requestHold(ctx, s, []string{"audit_outbox_backlog:test"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := a.releaseRecovered(ctx, map[holdScope]bool{}); err != nil || a.HeldScopes() != 0 || objects.creates != 1 {
		t.Fatalf("replica A: %v held=%d probes=%d", err, a.HeldScopes(), objects.creates)
	}
	if err := b.releaseRecovered(ctx, map[holdScope]bool{}); err != nil || b.HeldScopes() != 0 || objects.creates != 2 {
		t.Fatalf("replica B kept released holds: %v held=%d probes=%d", err, b.HeldScopes(), objects.creates)
	}
}

// TOCTOU regression: a release round snapshots a clear measurement, then a
// newer measurement shows the backlog is back above the limit and re-requests
// the hold. The round must not release the hold on its stale snapshot.
func TestReleaseRoundYieldsToNewerMeasurement(t *testing.T) {
	ctx := context.Background()
	pki := fx.NewPKI(t, t.TempDir())
	cert, _, _ := pki.Issue(t, "exporter", fx.ExporterSAN, false, x509.ExtKeyUsageClientAuth)
	health := fx.NewControlHealth(t, pki)
	r := &HealthReporter{Client: pki.ServiceClient(t, cert, fx.ControlHealthSAN), URL: health.URL, Prober: &ExportProber{Objects: &probeObjects{data: map[string][]byte{}}, Bucket: "audit-evidence"}}
	lagging := []auditdb.ExportBacklogsRow{{SourceClass: "business", PendingRecords: 3, PendingBytes: 150, OldestAgeSeconds: 200}}
	global := holdScope{"global", "*"}
	r.commitMeasurement(lagging, true)
	if err := r.requestHold(ctx, global, []string{"audit_outbox_backlog:test"}); err != nil {
		t.Fatal(err)
	}
	r.commitMeasurement(nil, true) // backlog cleared
	snapshotTaken, newerCommitted := make(chan struct{}), make(chan struct{})
	r.afterSnapshot = func() {
		close(snapshotTaken)
		<-newerCommitted
	}
	done := make(chan error, 1)
	go func() { done <- r.Release(ctx) }()
	<-snapshotTaken
	// Concurrent Report: newer measurement first, then the hold request.
	r.commitMeasurement(lagging, true)
	if err := r.requestHold(ctx, global, []string{"audit_outbox_backlog:test"}); err != nil {
		t.Fatal(err)
	}
	close(newerCommitted)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_, holds, probes := health.Snapshot()
	for _, h := range holds {
		if h.ReleasedAt != nil {
			t.Fatalf("stale measurement released a hold the newer measurement keeps: %+v", h)
		}
	}
	if len(probes) != 0 || r.HeldScopes() != 1 {
		t.Fatalf("stale round acted: probes=%d held=%d", len(probes), r.HeldScopes())
	}
	// Once a newer measurement clears the backlog, the next round releases.
	r.afterSnapshot = nil
	r.commitMeasurement(nil, true)
	if err := r.Release(ctx); err != nil || r.HeldScopes() != 0 {
		t.Fatalf("release after clear measurement: %v held=%d", err, r.HeldScopes())
	}
}

// #159 release responses: the same request on a released hold returns the
// stored 200; a different request is 409 (logged, hold forgotten, no retry
// loop); insufficient evidence is also 409; an unknown hold is 404.
func TestReleaseResponsesFollowContract(t *testing.T) {
	ctx := context.Background()
	pki := fx.NewPKI(t, t.TempDir())
	cert, _, _ := pki.Issue(t, "exporter", fx.ExporterSAN, false, x509.ExtKeyUsageClientAuth)
	health := fx.NewControlHealth(t, pki)
	var logged []error
	r := &HealthReporter{Client: pki.ServiceClient(t, cert, fx.ControlHealthSAN), URL: health.URL,
		Prober: &ExportProber{Objects: &probeObjects{data: map[string][]byte{}}, Bucket: "audit-evidence"}, OnReleaseError: func(err error) { logged = append(logged, err) }}
	global := holdScope{"global", "*"}
	if err := r.requestHold(ctx, global, []string{"audit_outbox_backlog:test"}); err != nil {
		t.Fatal(err)
	}
	holdID := r.held[global]
	probeID, err := r.postProbe(ctx, global, "pass", []string{"gs://audit-evidence/probes/x#1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.release(ctx, holdID, probeID, []string{"gs://audit-evidence/probes/x#1"}); err != nil {
		t.Fatal(err)
	}
	if err := r.release(ctx, holdID, probeID, []string{"gs://audit-evidence/probes/x#1"}); err != nil {
		t.Fatalf("identical retry must return the stored response: %v", err)
	}
	other, _ := r.postProbe(ctx, global, "pass", []string{"gs://audit-evidence/probes/y#1"})
	if err := r.release(ctx, holdID, other, []string{"gs://audit-evidence/probes/y#1"}); !errors.Is(err, errHoldConflict) {
		t.Fatalf("different request on released hold: %v", err)
	}
	if err := r.release(ctx, "11111111-2222-4333-8444-555555555555", other, []string{}); !errors.Is(err, errHoldGone) {
		t.Fatalf("unknown hold: %v", err)
	}
	// Insufficient evidence on an open hold is 409 too.
	if err := r.requestHold(ctx, holdScope{"node", "6a6f2b8e-34c1-4d55-8a0c-0b6f0f2f7a10"}, []string{"audit_outbox_backlog:test"}); err != nil {
		t.Fatal(err)
	}
	failed, _ := r.postProbe(ctx, holdScope{"node", "6a6f2b8e-34c1-4d55-8a0c-0b6f0f2f7a10"}, "fail", []string{})
	if err := r.release(ctx, r.held[holdScope{"node", "6a6f2b8e-34c1-4d55-8a0c-0b6f0f2f7a10"}], failed, []string{}); !errors.Is(err, errHoldConflict) {
		t.Fatalf("insufficient evidence: %v", err)
	}
	// In a release round the 409 is logged and the hold forgotten, no error.
	r.mu.Lock()
	r.held = map[holdScope]string{global: holdID}
	r.heldGen = map[holdScope]uint64{global: 0}
	r.mu.Unlock()
	// The owned listing used to classify the 409 also brings back the still
	// open node hold; the released global hold is forgotten.
	if err := r.releaseRecovered(ctx, map[holdScope]bool{global: false, {"node", "6a6f2b8e-34c1-4d55-8a0c-0b6f0f2f7a10"}: true}); err != nil || len(logged) != 1 || !errors.Is(logged[0], errHoldConflict) {
		t.Fatalf("409 handling: %v held=%d logged=%v", err, r.HeldScopes(), logged)
	}
	r.mu.Lock()
	_, stillGlobal := r.held[global]
	r.mu.Unlock()
	if stillGlobal || r.HeldScopes() != 1 {
		t.Fatalf("released hold kept or open hold lost: held=%d", r.HeldScopes())
	}
}
