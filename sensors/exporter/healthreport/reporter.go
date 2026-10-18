package healthreport

import (
	"context"
	"errors"
	"sync"
	"time"
)

type Sink interface {
	ReportLease(context.Context, Lease) error
	RequestHold(context.Context, Hold) error
}

type Config struct {
	SourceID, NodeUID, Version string
	SensorGeneration           int64
	// Only actual stored evidence references may be supplied. Empty means no
	// durable references are available; local diagnostics are not fabricated IDs.
	EvidenceRefs []string
	Monitor      *Monitor
	Sink         Sink
}

type Reporter struct {
	mu        sync.Mutex
	config    Config
	holdAcked bool
}

func NewReporter(c Config) (*Reporter, error) {
	if c.SourceID == "" || c.NodeUID == "" || c.Version == "" || c.SensorGeneration < 1 || c.SensorGeneration > 9007199254740991 || c.Monitor == nil || c.Sink == nil {
		return nil, errors.New("incomplete sensor health configuration")
	}
	c.EvidenceRefs = append([]string{}, c.EvidenceRefs...)
	return &Reporter{config: c}, nil
}

// Report makes independent bounded lease and hold attempts. A lease transport
// failure must not suppress the hold request. Only a validated created/existing
// acknowledgement suppresses repeat hold requests during this process lifetime.
func (r *Reporter) Report(ctx context.Context, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.config
	state := c.Monitor.State(now)
	observed := "unhealthy"
	if state.Healthy {
		observed = "healthy"
	}
	lease := Lease{SourceID: c.SourceID, Component: "node-sensors", Scope: "node", ScopeID: c.NodeUID, ActiveVersion: &c.Version, SensorGeneration: &c.SensorGeneration, LeaseUntil: now.UTC().Add(15 * time.Second), ReportedAt: now.UTC(), ObservedState: observed}
	leaseResult := make(chan error, 1)
	go func() {
		call, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		leaseResult <- c.Sink.ReportLease(call, lease)
	}()
	var holdErr error
	if state.NeedsHold && !r.holdAcked {
		call, cancel := context.WithTimeout(ctx, 4*time.Second)
		holdErr = c.Sink.RequestHold(call, Hold{Scope: "node", ScopeID: c.NodeUID, Reason: "sensor_degraded", EvidenceRefs: c.EvidenceRefs})
		cancel()
		r.holdAcked = holdErr == nil
	}
	return errors.Join(<-leaseResult, holdErr)
}

// Run sends 5-second leases with a 15-second TTL. A 1-second timer detects ACK
// stagnation even while the delivery worker is blocked in its own retry loop.
// Explicit durability/rotation failures wake it immediately. Calls already in
// flight finish or time out within four seconds before the next report.
func (r *Reporter) Run(ctx context.Context, onError func(error)) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastReport time.Time
	var previous State
	for {
		now := time.Now()
		state := r.config.Monitor.State(now)
		if lastReport.IsZero() || now.Sub(lastReport) >= 5*time.Second || state != previous {
			if err := r.Report(ctx, now); err != nil && ctx.Err() == nil && onError != nil {
				onError(err)
			}
			lastReport, previous = now, state
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.config.Monitor.wake:
		case <-tick.C:
		}
	}
}
