package healthreport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/tailer"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

func TestSupervisorClassifiesWorkerFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		hold bool
	}{
		{"rotation", tailer.ErrRotationLoss, true}, {"truncate", tailer.ErrTruncated, true}, {"incomplete", tailer.ErrIncompleteRotatedRecord, true}, {"full", wal.ErrFull, true}, {"parse", errors.New("private event contents"), false}, {"unexpected return", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := openHealthWAL(t, t.TempDir(), "epoch")
			m := NewMonitor()
			s := &Supervisor{journal: j, monitor: m}
			s.workerStopped(tc.err)
			state := m.State(time.Now())
			if state.Healthy || state.NeedsHold != tc.hold {
				t.Fatal(state)
			}
		})
	}
}
func TestSupervisorReportsAfterWorkerStopsAndDuringSlowMetrics(t *testing.T) {
	j := openHealthWAL(t, t.TempDir(), "epoch")
	m := NewMonitor()
	sink := &fakeSink{seen: make(chan Lease, 8)}
	blocked := make(chan struct{})
	source := &blockingMetrics{started: blocked}
	sampler, _ := NewSampler(j, source, nil, m)
	r := reporter(t, m, sink)
	s := &Supervisor{journal: j, monitor: m, sampler: sampler, reporter: r,
		acquisition: func(ctx context.Context) error {
			select {
			case <-blocked:
				return tailer.ErrRotationLoss
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		delivery: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, nil) }()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		sink.mu.Lock()
		held := len(sink.holds) > 0
		unhealthy := len(sink.leases) > 0 && sink.leases[len(sink.leases)-1].ObservedState == "unhealthy"
		sink.mu.Unlock()
		if held && unhealthy {
			break
		}
		select {
		case <-deadline:
			t.Fatal("blocked metrics suppressed worker failure reporting")
		case <-ticker.C:
		}
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("workers not joined on cancel")
	}
}

type blockingMetrics struct {
	started chan struct{}
	once    sync.Once
}

func (s *blockingMetrics) Scrape(ctx context.Context) (GlobalLoss, error) {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return GlobalLoss{}, ctx.Err()
}
