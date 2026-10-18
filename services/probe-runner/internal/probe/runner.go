package probe

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Timing of TASK-10 3.2 (health_contract kernel_probe_*).
const (
	// Period is kernel_probe_interval_seconds. Consecutive passes count only
	// when their stimulus_at values are 58-62s apart, so cycles are anchored
	// to the first one and never drift with stimulus or report time.
	Period = 60 * time.Second
	// JudgeDelay is kernel_probe_judge_delay_seconds: collection lag 10s plus
	// clock skew and margin.
	JudgeDelay = 25 * time.Second
	// RetryInterval spaces repeated reports of one stimulus while its kernel
	// batch is not committed yet (409) or control-health is unavailable.
	RetryInterval = 3 * time.Second
	// PassDeadline: control-health accepts a pass whose stimulus_at is at
	// most 40s old. The runner stops retrying a pass 2s (the clock skew)
	// before that.
	PassDeadline = 38 * time.Second
)

// Runner gives every kind its stimulus once per Period and reports it.
type Runner struct {
	NodeUID, BootID string
	Stimuli         map[string]Stimulus
	Send            func(context.Context, Result) (int, error)
	Log             *slog.Logger
	// Now and After replace the clock in tests.
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// sleepUntil waits for t and reports false when ctx ended first.
func (r *Runner) sleepUntil(ctx context.Context, t time.Time) bool {
	d := t.Sub(r.now())
	if d <= 0 {
		return ctx.Err() == nil
	}
	after := time.After
	if r.After != nil {
		after = r.After
	}
	select {
	case <-ctx.Done():
		return false
	case <-after(d):
		return true
	}
}

// Run starts the first cycle at once (a new Pod on a new or rebooted node
// probes immediately) and then every Period until ctx ends. Each kind runs
// in its own goroutine: the kinds record disjoint event types, and a slow
// stimulus or report of one kind never shifts another kind's stimulus_at.
func (r *Runner) Run(ctx context.Context) {
	start := r.now()
	var wg sync.WaitGroup
	defer wg.Wait()
	for n := 0; ; n++ {
		if !r.sleepUntil(ctx, start.Add(time.Duration(n)*Period)) {
			return
		}
		for _, kind := range Kinds {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.Probe(ctx, kind)
			}()
		}
	}
}

// Probe gives one stimulus, waits JudgeDelay and reports it. It returns the
// last report sent and its HTTP status (0: none answered).
//
// A stimulus that ran as intended is reported as pass with its stimulus_at;
// control-health then looks for the kernel events itself. 409 means the
// events are not there (yet): the runner repeats the same stimulus_at
// every RetryInterval until PassDeadline and then reports fail, because the
// required events did not arrive in time (TASK-10 3.2 "fail if any one
// is missing"). A stimulus that did not run as intended is reported as fail at
// once. The runner never reports unknown: it cannot tell a broken
// collection path from missing events.
// SPEC-QUESTION: TASK-10 3.2 does not say what the runner reports when the
// kernel batch stays uncommitted past the 40s stimulus bound; fail is used.
func (r *Runner) Probe(ctx context.Context, kind string) (Result, int) {
	at := r.now().UTC()
	outcome := "pass"
	if err := r.Stimuli[kind](ctx); err != nil {
		outcome = "fail"
		r.Log.Warn("stimulus did not run as intended", "probe_kind", kind, "error", err.Error())
	}
	res := Result{ProbeKind: kind, NodeUID: r.NodeUID, BootID: r.BootID, StimulusAt: at, Outcome: outcome,
		EvidenceRefs: []string{StimulusRef(kind, at)}}
	if !r.sleepUntil(ctx, at.Add(JudgeDelay)) {
		return res, 0
	}
	return r.deliver(ctx, res)
}

func retryable(status int, outcome string) bool {
	return status == 0 || status == http.StatusTooManyRequests || status >= 500 ||
		(status == http.StatusConflict && outcome == "pass")
}

func (r *Runner) deliver(ctx context.Context, res Result) (Result, int) {
	deadline := res.StimulusAt.Add(PassDeadline)
	if res.Outcome != "pass" {
		// A fail is not bound to the stimulus age; keep it until the next cycle.
		deadline = res.StimulusAt.Add(Period)
	}
	for {
		status, err := r.Send(ctx, res)
		if status == http.StatusCreated {
			r.Log.Info("probe reported", "probe_kind", res.ProbeKind, "outcome", res.Outcome, "stimulus_at", res.StimulusAt)
			return res, status
		}
		if !retryable(status, res.Outcome) {
			r.Log.Error("probe report rejected", "probe_kind", res.ProbeKind, "outcome", res.Outcome, "status", status, "error", errText(err))
			return res, status
		}
		next := r.now().Add(RetryInterval)
		if next.After(deadline) {
			if status == http.StatusConflict && res.Outcome == "pass" {
				r.Log.Warn("kernel evidence not found in time", "probe_kind", res.ProbeKind, "stimulus_at", res.StimulusAt)
				res.Outcome, deadline = "fail", res.StimulusAt.Add(Period)
				continue
			}
			r.Log.Error("probe report not delivered", "probe_kind", res.ProbeKind, "outcome", res.Outcome, "status", status, "error", errText(err))
			return res, status
		}
		if !r.sleepUntil(ctx, next) {
			return res, status
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
