package healthreport

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

type LossSource interface {
	Scrape(context.Context) (GlobalLoss, error)
}
type JournalHealth interface {
	HealthSnapshot() (wal.HealthSnapshot, error)
}

// CaptureVerifier must check actual loaded hooks, active rule hash, filtering,
// rate/aggregation settings and current probe evidence for this node/generation.
// A successful metrics scrape, live worker, or contiguous WAL is not evidence.
// Implementations must honor ctx. There is deliberately no default verifier.
type CaptureVerifier interface {
	VerifyCapture(context.Context) (bool, error)
}

// Sampler bridges the real atomic WAL view and pinned metrics to Monitor.
// Reporter runs independently so a slow scrape cannot suppress unhealthy leases
// or ACK stagnation detection. Sampling timestamps are taken BEFORE I/O so slow
// results cannot rejuvenate stale evidence.
type Sampler struct {
	mu      sync.Mutex
	journal JournalHealth
	loss    LossSource
	capture CaptureVerifier
	monitor *Monitor
}

func NewSampler(j JournalHealth, l LossSource, c CaptureVerifier, m *Monitor) (*Sampler, error) {
	if j == nil || l == nil || m == nil {
		return nil, errors.New("incomplete health sampler")
	}
	return &Sampler{journal: j, loss: l, capture: c, monitor: m}, nil
}
func (s *Sampler) Sample(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	started := time.Now()
	call, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	loss, lossErr := s.loss.Scrape(call)
	// A late scrape is unavailable. Keep an on-time partial loss sample even
	// if subsequent capture verification fails, so known loss is not hidden.
	if call.Err() != nil {
		loss = GlobalLoss{}
	}
	var verified bool
	var captureErr error
	if s.capture != nil {
		verified, captureErr = s.capture.VerifyCapture(call)
	}
	if call.Err() != nil || lossErr != nil || captureErr != nil {
		verified = false
	}
	w, err := s.journal.HealthSnapshot()
	if err != nil {
		s.monitor.DurabilityFailed()
		return errors.New("WAL health unavailable")
	}
	err = s.monitor.Observe(started, Sample{CaptureVerified: verified, GlobalMetrics: true, GlobalLoss: loss, Used: w.Used, Capacity: w.Capacity, Pending: w.Pending, AckProgress: w.AckProgress})
	// Expose fixed diagnostics only; upstream errors can contain request material.
	if lossErr != nil || captureErr != nil || call.Err() != nil {
		return errors.Join(err, errors.New("capture or metrics verification unavailable"))
	}
	return err
}
func (s *Sampler) Run(ctx context.Context, onError func(error)) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.Sample(ctx); err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
