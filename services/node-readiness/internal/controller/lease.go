package controller

import (
	"context"
	"log/slog"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/node-readiness/internal/controlhealth"
)

const (
	LeaseComponent = "node-readiness"
	LeaseScope     = "global"
	// SPEC-QUESTION: COMMON does not fix scope_id for global leases; health.holds
	// uses '*' for global scope, so the lease uses the same value.
	LeaseScopeID = "*"
)

// LeaseReporter posts the controller's own ControlHealthLease.
type LeaseReporter interface {
	ReportLease(ctx context.Context, l controlhealth.Lease) (*controlhealth.LeaseAck, error)
}

type LeaseConfig struct {
	SourceID string
	Version  string
	Interval time.Duration // heartbeat_interval_seconds: 5
	TTL      time.Duration // lease_ttl_seconds: 15
	Logger   *slog.Logger
	Now      func() time.Time
}

// BuildLease returns the lease for the current controller state.
func BuildLease(cfg LeaseConfig, state string) controlhealth.Lease {
	now := cfg.Now().UTC()
	var version *string
	if cfg.Version != "" {
		v := cfg.Version
		version = &v
	}
	return controlhealth.Lease{
		SourceID:      cfg.SourceID,
		Component:     LeaseComponent,
		Scope:         LeaseScope,
		ScopeID:       LeaseScopeID,
		ActiveVersion: version,
		LeaseUntil:    now.Add(cfg.TTL),
		ObservedState: state,
		ReportedAt:    now,
	}
}

// RunLeaseReporter reports every Interval until ctx is cancelled. If reports
// stop, TASK-10 expires the lease and places a global lease_expired hold.
// The lease is not renewed while state is unhealthy: the controller cannot
// vouch for taint state then, and lease expiry is the signal TASK-10 acts on.
func RunLeaseReporter(ctx context.Context, r LeaseReporter, cfg LeaseConfig, state func() string) {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 15 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	report := func() {
		st := state()
		if st == "unhealthy" {
			cfg.Logger.Warn("controller unhealthy; lease not renewed")
			return
		}
		rctx, cancel := context.WithTimeout(ctx, cfg.Interval)
		defer cancel()
		if _, err := r.ReportLease(rctx, BuildLease(cfg, st)); err != nil {
			cfg.Logger.Warn("lease report failed", "err", err)
		}
	}
	report()
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report()
		}
	}
}
