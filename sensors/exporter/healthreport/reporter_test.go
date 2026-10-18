package healthreport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeSink struct {
	mu                sync.Mutex
	leases            []Lease
	holds             []Hold
	leaseErr, holdErr error
	seen              chan Lease
	blockLease        bool
}

func (s *fakeSink) ReportLease(ctx context.Context, l Lease) error {
	s.mu.Lock()
	s.leases = append(s.leases, l)
	err, block := s.leaseErr, s.blockLease
	s.mu.Unlock()
	if s.seen != nil {
		s.seen <- l
	}
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}
func (s *fakeSink) RequestHold(_ context.Context, h Hold) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.holds = append(s.holds, h)
	return s.holdErr
}
func reporter(t *testing.T, m *Monitor, sink Sink) *Reporter {
	t.Helper()
	r, err := NewReporter(Config{SourceID: "sensor-source", NodeUID: "node-uid", Version: "version", SensorGeneration: 3, Monitor: m, Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHoldIsIndependentAndRetriesUntilAcknowledged(t *testing.T) {
	m := NewMonitor()
	m.RotationLost()
	s := &fakeSink{leaseErr: errors.New("lease unavailable"), holdErr: errors.New("hold unavailable")}
	r := reporter(t, m, s)
	now := time.Now()
	if r.Report(context.Background(), now) == nil {
		t.Fatal("lost errors")
	}
	s.holdErr = nil
	if r.Report(context.Background(), now.Add(time.Second)) == nil {
		t.Fatal("lease error lost")
	}
	if r.Report(context.Background(), now.Add(2*time.Second)) == nil {
		t.Fatal("lease error lost")
	}
	if len(s.leases) != 3 || len(s.holds) != 2 {
		t.Fatalf("leases=%d holds=%d", len(s.leases), len(s.holds))
	}
	l, h := s.leases[0], s.holds[0]
	if l.ObservedState != "unhealthy" || l.Component != "node-sensors" || l.Scope != "node" || l.ScopeID != "node-uid" || l.LeaseUntil.Sub(l.ReportedAt) != 15*time.Second || *l.SensorGeneration != 3 {
		t.Fatalf("%+v", l)
	}
	if h.ScopeID != "node-uid" || h.Reason != "sensor_degraded" || h.EvidenceRefs == nil {
		t.Fatalf("%+v", h)
	}
}

func TestBlockedLeaseDoesNotDelayHold(t *testing.T) {
	m := NewMonitor()
	m.DurabilityFailed()
	s := &fakeSink{blockLease: true}
	r := reporter(t, m, s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Report(ctx, time.Now()) }()
	deadline := time.After(time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		s.mu.Lock()
		n := len(s.holds)
		s.mu.Unlock()
		if n == 1 {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("hold blocked behind lease")
		case <-tick.C:
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRunWakesOnFailureAndCancels(t *testing.T) {
	m := NewMonitor()
	if err := m.Observe(time.Now(), goodSample()); err != nil {
		t.Fatal(err)
	}
	s := &fakeSink{seen: make(chan Lease, 3)}
	r := reporter(t, m, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, nil) }()
	select {
	case l := <-s.seen:
		if l.ObservedState != "healthy" {
			t.Fatal(l)
		}
	case <-time.After(time.Second):
		t.Fatal("no initial lease")
	}
	m.RotationLost()
	select {
	case l := <-s.seen:
		if l.ObservedState != "unhealthy" {
			t.Fatal(l)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("failure waited for periodic lease")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("did not cancel")
	}
}
