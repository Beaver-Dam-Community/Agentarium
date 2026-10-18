package healthreport

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/acquire"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/delivery"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/tailer"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

// Supervisor owns the lifetime of already-configured acquisition, delivery,
// sampling and health reporting loops. Construction injects the same journal
// into acquisition, delivery and the atomic health sampler. The real normalizer, certificate
// source, source registration and CaptureVerifier are installation prerequisites.
// None are synthesized by this package.
type SupervisorConfig struct {
	Journal     *wal.Journal
	Acquisition acquire.Config
	Delivery    delivery.Config
	Metrics     LossSource
	Capture     CaptureVerifier
	Reporting   Config
}
type Supervisor struct {
	journal               *wal.Journal
	acquisition, delivery func(context.Context) error
	sampler               *Sampler
	reporter              *Reporter
	monitor               *Monitor
}

func NewSupervisor(c SupervisorConfig) (*Supervisor, error) {
	if c.Journal == nil {
		return nil, errors.New("incomplete sensor workers")
	}
	c.Acquisition.Journal = c.Journal
	c.Delivery.Journal = c.Journal
	collector, err := acquire.New(c.Acquisition)
	if err != nil {
		return nil, err
	}
	pump, err := delivery.New(c.Delivery)
	if err != nil {
		return nil, err
	}
	monitor := NewMonitor()
	sampler, err := NewSampler(c.Journal, c.Metrics, c.Capture, monitor)
	if err != nil {
		return nil, err
	}
	c.Reporting.Monitor = monitor
	reporter, err := NewReporter(c.Reporting)
	if err != nil {
		return nil, err
	}
	return &Supervisor{journal: c.Journal, acquisition: collector.Run, delivery: pump.Run, sampler: sampler, reporter: reporter, monitor: monitor}, nil
}

// Run keeps reporting unhealthy leases and retrying holds after either worker
// stops. It does not restart a failed worker or release holds. onError may be
// called concurrently and only receives fixed diagnostics from this supervisor.
// Workers and external verifier implementations must honor cancellation.
func (s *Supervisor) Run(ctx context.Context, onError func(error)) error {
	var wg sync.WaitGroup
	report := func(message string) {
		if onError != nil && ctx.Err() == nil {
			onError(errors.New(message))
		}
	}
	worker := func(run func(context.Context) error) {
		defer wg.Done()
		err := run(ctx)
		if ctx.Err() != nil {
			return
		}
		s.workerStopped(err)
		report("sensor worker stopped; WAL retained")
	}
	wg.Add(4)
	go worker(s.acquisition)
	go worker(s.delivery)
	go func() {
		defer wg.Done()
		_ = s.sampler.Run(ctx, func(error) { report("sensor health sampling failed") })
	}()
	go func() {
		defer wg.Done()
		_ = s.reporter.Run(ctx, func(error) { report("sensor health reporting failed") })
	}()
	wg.Wait()
	return ctx.Err()
}
func (s *Supervisor) workerStopped(err error) {
	switch {
	case errors.Is(err, tailer.ErrRotationLoss), errors.Is(err, tailer.ErrTruncated), errors.Is(err, tailer.ErrIncompleteRotatedRecord):
		s.monitor.RotationLost()
	case errors.Is(err, wal.ErrFull), errors.Is(err, syscall.ENOSPC):
		s.monitor.DurabilityFailed()
	default:
		if _, e := s.journal.HealthSnapshot(); e != nil {
			s.monitor.DurabilityFailed()
		} else {
			s.monitor.WorkerStopped()
		}
	}
}

// Healthy is the monitor's current healthy state: fresh verified capture,
// known loss, no durability/rotation/worker failure and no hold. The node
// observation responder reports nothing while it is false.
func (s *Supervisor) Healthy(now time.Time) bool { return s.monitor.State(now).Healthy }
