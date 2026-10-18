package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/healthreport"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

type holdScope struct {
	Scope string `json:"scope"`
	ID    string `json:"scope_id"`
}

// backlogState uses TASK-07 section 3.2's initial limits. Only unacknowledged
// rows participate; sequence gaps and source event timestamps are not export lag.
func backlogState(rows []auditdb.ExportBacklogsRow) (string, []holdScope, error) {
	state := "healthy"
	holds := []holdScope{}
	seen := map[holdScope]bool{}
	for _, r := range rows {
		if r.PendingRecords < 1 || r.PendingBytes < 1 || r.OldestAgeSeconds < 0 {
			return "unhealthy", nil, errors.New("invalid export backlog")
		}
		degraded, hold := false, false
		scope := holdScope{Scope: "global", ID: "*"}
		switch r.SourceClass {
		case "business":
			degraded = r.OldestAgeSeconds > 10
			hold = r.OldestAgeSeconds > 120 || r.PendingRecords > 10000
		case "kernel":
			degraded = r.OldestAgeSeconds > 30
			hold = r.OldestAgeSeconds > 300 || r.PendingRecords > 200000 || r.PendingBytes > 512*1024*1024
			scope = holdScope{Scope: "node", ID: r.NodeUid}
		case "lifecycle":
			degraded = r.OldestAgeSeconds > 10
			hold = r.OldestAgeSeconds > 120 || r.PendingRecords > 50000
			scope = holdScope{Scope: "node", ID: r.NodeUid}
		case "decision_input":
			degraded = r.OldestAgeSeconds > 60
		default:
			return "unhealthy", nil, errors.New("unknown export class")
		}
		if degraded || hold {
			state = "degraded"
		}
		if hold {
			// Do not replace a missing observed node with the exporter's own node.
			if scope.Scope == "node" && !validUUID(scope.ID) {
				return "unhealthy", nil, errors.New("backlogged observation has no authoritative node")
			}
			if !seen[scope] {
				seen[scope] = true
				holds = append(holds, scope)
			}
		}
	}
	return state, holds, nil
}

// pressuredScopes lists hold scopes whose backlog is at or above the degraded
// limit. A remembered export_lag hold may be released only outside this set.
// Decision-input delay never holds and does not block business release.
func pressuredScopes(rows []auditdb.ExportBacklogsRow) map[holdScope]bool {
	out := map[holdScope]bool{}
	for _, r := range rows {
		switch r.SourceClass {
		case "business":
			if r.OldestAgeSeconds > 10 || r.PendingRecords > 10000 {
				out[holdScope{"global", "*"}] = true
			}
		case "kernel":
			if r.OldestAgeSeconds > 30 || r.PendingRecords > 200000 || r.PendingBytes > 512*1024*1024 {
				out[holdScope{"node", r.NodeUid}] = true
			}
		case "lifecycle":
			if r.OldestAgeSeconds > 10 || r.PendingRecords > 50000 {
				out[holdScope{"node", r.NodeUid}] = true
			}
		}
	}
	return out
}

// HealthReporter measures the real outbox and reports the exporter's global
// lease. Hold scopes come only from stored record nodes. It remembers the
// export_lag holds it obtained; when a held scope drops below the degraded
// limit and Prober passes, it reports the probe result and releases the hold
// through the TASK-10 API (TASK-07 3.2.1). Backlog decrease alone never
// releases a hold, and without a Prober no release is attempted.
type HealthReporter struct {
	Pool                   *pgxpool.Pool
	Client                 *http.Client
	URL, SourceID, Version string
	Prober                 *ExportProber
	// Interval defaults to the required five-second lease report.
	Interval time.Duration
	// OnReleaseError receives probe/release failures; they never change the
	// audit-export lease state.
	OnReleaseError func(error)
	mu             sync.Mutex
	held           map[holdScope]string
	// heldGen is the measurement generation at which each hold was requested
	// or recovered. A release round may act only on holds older than the
	// measurement it uses, and aborts if a newer measurement appears.
	heldGen   map[holdScope]uint64
	gen       uint64
	pressured map[holdScope]bool
	measured  bool
	recover   chan struct{}
	// afterSnapshot is a test hook run after a release round takes its
	// measurement snapshot.
	afterSnapshot func()
}

// commitMeasurement publishes a backlog measurement before any hold request
// based on it, so a concurrent release round sees it or aborts.
func (r *HealthReporter) commitMeasurement(rows []auditdb.ExportBacklogsRow, ok bool) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gen++
	if ok {
		r.pressured, r.measured = pressuredScopes(rows), true
	} else {
		r.pressured, r.measured = nil, false
	}
	return r.gen
}

func (r *HealthReporter) remember(scope holdScope, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.held == nil {
		r.held, r.heldGen = map[holdScope]string{}, map[holdScope]uint64{}
	}
	r.held[scope], r.heldGen[scope] = id, r.gen
}

func (r *HealthReporter) Report(ctx context.Context) error {
	if r.Pool == nil || r.Client == nil || r.URL == "" || r.SourceID == "" || r.Version == "" {
		return errors.New("incomplete export health configuration")
	}
	rows, err := auditdb.New(r.Pool).ExportBacklogs(ctx)
	state := "unhealthy"
	var holds []holdScope
	if err == nil {
		state, holds, err = backlogState(rows)
	}
	r.commitMeasurement(rows, err == nil)
	for _, hold := range holds {
		if e := r.requestHold(ctx, hold, backlogEvidence(rows, hold)); e != nil {
			err = errors.Join(err, e)
			state = "unhealthy"
		}
	}
	// Release runs separately (Release) with its own deadline, so probes never
	// consume this lease report's window and release failures do not change
	// the audit-export observed_state (TASK-07 3.2.1).
	now := time.Now().UTC()
	lease := healthreport.Lease{SourceID: r.SourceID, Component: "audit-export", Scope: "global", ScopeID: "*", ActiveVersion: &r.Version, LeaseUntil: now.Add(15 * time.Second), ObservedState: state, ReportedAt: now}
	return errors.Join(err, healthreport.SendLease(ctx, r.Client, r.URL, lease))
}

// backlogEvidence describes the measured backlog behind a hold request.
func backlogEvidence(rows []auditdb.ExportBacklogsRow, scope holdScope) []string {
	refs := []string{}
	at := time.Now().UTC().Format(time.RFC3339)
	for _, row := range rows {
		rowScope := holdScope{"global", "*"}
		if row.SourceClass == "kernel" || row.SourceClass == "lifecycle" {
			rowScope = holdScope{"node", row.NodeUid}
		}
		if row.SourceClass == "decision_input" || rowScope != scope {
			continue
		}
		refs = append(refs, "audit_outbox_backlog:"+row.SourceClass+":"+scope.Scope+":"+scope.ID+
			":oldest_age_s="+strconv.FormatInt(int64(row.OldestAgeSeconds), 10)+":records="+strconv.FormatInt(row.PendingRecords, 10)+":at="+at)
	}
	return refs
}

func (r *HealthReporter) requestHold(ctx context.Context, scope holdScope, evidence []string) error {
	if evidence == nil {
		evidence = []string{}
	}
	body, err := json.Marshal(struct {
		holdScope
		Reason   string   `json:"reason"`
		Evidence []string `json:"evidence_refs"`
	}{scope, "export_lag", evidence})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", r.URL+"/internal/holds", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 || resp.StatusCode != 200 {
		return errors.New("export hold not accepted")
	}
	var ack struct {
		ID       string `json:"hold_id"`
		Decision string `json:"decision"`
	}
	if json.Unmarshal(raw, &ack) != nil || !validUUID(ack.ID) || (ack.Decision != "created" && ack.Decision != "existing") {
		return errors.New("invalid export hold acknowledgement")
	}
	r.remember(scope, ack.ID)
	return nil
}

// Release probes and releases remembered holds whose scope recovered in the
// latest lease report. It needs a successful backlog measurement first.
func (r *HealthReporter) Release(ctx context.Context) error {
	r.mu.Lock()
	measured, pressured, gen := r.measured, r.pressured, r.gen
	r.mu.Unlock()
	if r.Prober == nil || !measured {
		return nil
	}
	return r.releaseRound(ctx, gen, pressured)
}

// releaseRecovered probes once per call (the probe does not depend on scope)
// and reports that result for every recovered remembered hold. A failed probe
// is still reported, and the hold stays.
// releaseRecovered treats pressured as a fresh measurement (tests and direct
// callers) and runs one release round on it.
func (r *HealthReporter) releaseRecovered(ctx context.Context, pressured map[holdScope]bool) error {
	r.mu.Lock()
	r.gen++
	gen := r.gen
	r.pressured, r.measured = pressured, true
	r.mu.Unlock()
	return r.releaseRound(ctx, gen, pressured)
}

// stillReleasable rechecks, under the lock, that the latest measurement
// still shows the scope below the limit and the hold was not (re)requested
// after the round's snapshot. Unrelated newer measurements do not abort the
// round, so frequent reports cannot starve release.
func (r *HealthReporter) stillReleasable(scope holdScope, gen uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.measured && !r.pressured[scope] && r.heldGen[scope] < gen
}

func (r *HealthReporter) releaseRound(ctx context.Context, gen uint64, pressured map[holdScope]bool) error {
	r.mu.Lock()
	candidates := map[holdScope]string{}
	for scope, id := range r.held {
		if !pressured[scope] && r.heldGen[scope] < gen {
			candidates[scope] = id
		}
	}
	hook := r.afterSnapshot
	r.mu.Unlock()
	if hook != nil {
		hook()
	}
	var errs error
	if len(candidates) == 0 {
		return nil
	}
	outcome, refs := r.Prober.Probe(ctx)
	for scope, holdID := range candidates {
		if !r.stillReleasable(scope, gen) {
			continue // a newer measurement keeps this hold
		}
		probeID, err := r.postProbe(ctx, scope, outcome, refs)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		if outcome != "pass" {
			errs = errors.Join(errs, errors.New("export probe failed"))
			continue
		}
		// Recheck right before the release call: a measurement committed after
		// the snapshot (possibly re-requesting this hold) must win.
		if !r.stillReleasable(scope, gen) {
			continue
		}
		// 404/409: another replica may already have released the shared hold,
		// or the evidence was insufficient (TASK-10 3.2). Forget it here; owned
		// hold recovery re-reads the open holds from control-health.
		err = r.release(ctx, holdID, probeID, refs)
		switch {
		case errors.Is(err, errHoldGone):
			// 404: control-health does not know the hold; re-read owned holds.
			r.RequestRecovery()
		case errors.Is(err, errHoldConflict):
			// 409 (#159) is either "already released by another request" or
			// "insufficient evidence"; the owned-hold listing tells them apart.
			open, lerr := r.holdStillOpen(ctx, holdID)
			if lerr != nil || open {
				errs = errors.Join(errs, err, lerr) // genuinely open: retry next round
				continue
			}
			if r.OnReleaseError != nil {
				r.OnReleaseError(fmt.Errorf("hold %s: %w; it was already released by another request, forgotten", holdID, errHoldConflict))
			}
		case err != nil:
			errs = errors.Join(errs, err)
			continue
		}
		r.mu.Lock()
		// A recovery during this release may have discovered a newer hold.
		if r.held[scope] == holdID {
			delete(r.held, scope)
			delete(r.heldGen, scope)
		}
		r.mu.Unlock()
	}
	return errs
}

// holdStillOpen re-reads the owned holds (replacing the remembered set) and
// reports whether holdID is still an open hold of this component.
func (r *HealthReporter) holdStillOpen(ctx context.Context, holdID string) (bool, error) {
	if _, err := r.RecoverHolds(ctx); err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range r.held {
		if id == holdID {
			return true, nil
		}
	}
	return false, nil
}

// errHoldGone is a 404: control-health no longer knows the hold.
var errHoldGone = errors.New("hold unknown to control-health")

// errHoldConflict is a 409 (#159): the hold is already released by another
// request, or the release evidence was insufficient. The wire does not tell
// these apart.
var errHoldConflict = errors.New("hold already released or release evidence insufficient")

func (r *HealthReporter) post(ctx context.Context, path string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", r.URL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err == nil && resp.StatusCode == 404 {
		return errHoldGone
	}
	if err == nil && resp.StatusCode == 409 {
		return errHoldConflict
	}
	if err != nil || len(data) > 65536 || (resp.StatusCode != 200 && resp.StatusCode != 201) {
		return errors.New("control-health request not accepted")
	}
	return json.Unmarshal(data, out)
}

// postProbe submits the COMMON probe-results wire. Node scope carries node_uid;
// the exporter cannot know the node boot, so boot_id is omitted.
func (r *HealthReporter) postProbe(ctx context.Context, scope holdScope, outcome string, refs []string) (string, error) {
	body := map[string]any{"probe_kind": "export", "scope": scope.Scope, "scope_id": scope.ID, "outcome": outcome, "evidence_refs": refs}
	if scope.Scope == "node" {
		body["node_uid"] = scope.ID
	}
	var ack struct {
		ID string `json:"probe_result_id"`
	}
	if err := r.post(ctx, "/internal/control-health/probe-results", body, &ack); err != nil {
		return "", err
	}
	if !validUUID(ack.ID) {
		return "", errors.New("invalid probe result acknowledgement")
	}
	return ack.ID, nil
}

// release uses the TASK-10 3.2 request form; the server builds release_ref.
func (r *HealthReporter) release(ctx context.Context, holdID, probeID string, refs []string) error {
	body := map[string]any{"justification": "export backlog below degraded limit and export probe passed", "evidence_refs": refs, "probe_result_ids": []string{probeID}}
	var ack struct {
		HoldID     string    `json:"hold_id"`
		ReleasedAt time.Time `json:"released_at"`
		ReleaseRef string    `json:"release_ref"`
	}
	if err := r.post(ctx, "/internal/holds/"+holdID+"/release", body, &ack); err != nil {
		return err
	}
	if ack.HoldID != holdID || ack.ReleasedAt.IsZero() || ack.ReleaseRef != "auto:audit-export:"+probeID {
		return errors.New("invalid hold release acknowledgement")
	}
	return nil
}

// ErrHoldListing marks a failed owned-hold listing; recovery is retried.
var ErrHoldListing = errors.New("owned hold listing unavailable")

// RecoverHolds reloads the open holds this component owns from control-health
// (GET /internal/holds?owner_component=audit-export, TASK-10 chapter 4) so a
// restarted exporter or new leader resumes probe-based release. Only
// export_lag holds of audit-export with a valid scope are accepted; anything
// else in the response is ignored, and nothing is released here.
func (r *HealthReporter) RecoverHolds(ctx context.Context) (int, error) {
	if r.Client == nil || r.URL == "" {
		return 0, errors.New("incomplete export health configuration")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", r.URL+"/internal/holds?owner_component=audit-export", nil)
	if err != nil {
		return 0, err
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return 0, errors.Join(ErrHoldListing, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 || resp.StatusCode != 200 {
		return 0, ErrHoldListing
	}
	var list struct {
		Holds []struct {
			ID      string    `json:"hold_id"`
			Scope   string    `json:"scope"`
			ScopeID string    `json:"scope_id"`
			Reason  string    `json:"reason"`
			Owner   string    `json:"owner_component"`
			Created time.Time `json:"created_at"`
		} `json:"holds"`
	}
	if json.Unmarshal(raw, &list) != nil || list.Holds == nil {
		return 0, ErrHoldListing
	}
	// Replace, never merge: control-health is the source of truth, so a hold
	// another replica released disappears here instead of being retried.
	held := map[holdScope]string{}
	for _, h := range list.Holds {
		valid := (h.Scope == "global" && h.ScopeID == "*") || (h.Scope == "node" && validUUID(h.ScopeID))
		if h.Owner != "audit-export" || h.Reason != "export_lag" || !validUUID(h.ID) || !valid {
			continue
		}
		held[holdScope{h.Scope, h.ScopeID}] = h.ID
	}
	r.mu.Lock()
	r.held, r.heldGen = held, map[holdScope]uint64{}
	for scope := range held {
		r.heldGen[scope] = r.gen // releasable only after a newer measurement
	}
	r.mu.Unlock()
	return len(held), nil
}

// RequestRecovery asks a running RecoverLoop to reload owned holds, e.g.
// after this replica takes over the manifest lease. It never blocks.
func (r *HealthReporter) RequestRecovery() {
	r.mu.Lock()
	if r.recover == nil {
		r.recover = make(chan struct{}, 1)
	}
	ch := r.recover
	r.mu.Unlock()
	select {
	case ch <- struct{}{}:
	default:
	}
}

// RecoverLoop recovers owned holds at start and on each RequestRecovery,
// retrying a failed listing with exponential backoff from base up to max.
func (r *HealthReporter) RecoverLoop(ctx context.Context, base, max time.Duration, onError func(error)) {
	r.mu.Lock()
	if r.recover == nil {
		r.recover = make(chan struct{}, 1)
	}
	ch := r.recover
	r.mu.Unlock()
	for {
		for delay := base; ; delay = min(delay*2, max) {
			call, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := r.RecoverHolds(call)
			cancel()
			if err == nil || ctx.Err() != nil {
				break
			}
			if onError != nil {
				onError(err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ch:
		}
	}
}

// HeldScopes returns the number of remembered export_lag holds.
func (r *HealthReporter) HeldScopes() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.held)
}

func (r *HealthReporter) Run(ctx context.Context, onError func()) {
	every := r.Interval
	if every <= 0 {
		every = 5 * time.Second
	}
	if r.Prober != nil {
		// Probe/release has its own loop and deadline so it can never delay or
		// fail the lease report.
		go func() {
			tick := time.NewTicker(every)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
				call, cancel := context.WithTimeout(ctx, 4*time.Second)
				err := r.Release(call)
				cancel()
				if err != nil && ctx.Err() == nil && r.OnReleaseError != nil {
					r.OnReleaseError(err)
				}
			}
		}()
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		call, cancel := context.WithTimeout(ctx, 4*time.Second)
		err := r.Report(call)
		cancel()
		if err != nil && ctx.Err() == nil && onError != nil {
			onError()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
