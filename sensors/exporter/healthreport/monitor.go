// Package healthreport implements the TASK-09 3.5 sensor failure reporting
// boundary. Samples must come from verified capture and durable WAL/ACK state,
// never from the presence of a heartbeat or a successful HTTP send alone.
package healthreport

import (
	"errors"
	"sync"
	"time"
)

const SampleMaxAge = 5 * time.Second

// DropCounters are cumulative counters mapped from the pinned sensor version.
// Each row is a required hook: process, connect, state, file. Each column is
// ring-buffer loss, listener overflow, export rate-limit drop. Missing metrics
// must set DropsKnown=false; zero is not a substitute for unavailable evidence.
type DropCounters [4][3]uint64

type Sample struct {
	CaptureVerified bool
	DropsKnown      bool
	Drops           DropCounters
	// GlobalMetrics selects the pinned, unattributed daemon-wide loss mapping.
	GlobalMetrics  bool
	GlobalLoss     GlobalLoss
	Used, Capacity int64
	Pending        bool
	// AckProgress is process-local cumulative progress after durable WAL Ack.
	// Count contiguous watermark advances across all epochs, not HTTP responses,
	// accepted IDs, or received_at. It must never decrease during this monitor.
	AckProgress uint64
}

type State struct {
	Healthy   bool
	NeedsHold bool
}

type Monitor struct {
	mu          sync.Mutex
	wake        chan struct{}
	last        time.Time
	sample      Sample
	dropsKnown  bool
	drops       DropCounters
	globalLoss  GlobalLoss
	unknownTill time.Time
	ackSince    time.Time
	held        bool
	failed      bool
}

func NewMonitor() *Monitor { return &Monitor{wake: make(chan struct{}, 1)} }

func (m *Monitor) notify() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Observe accepts a fresh, atomic local snapshot. The caller samples at least
// once a second and uses a monotonic clock. Invalid samples cannot clear failure.
func (m *Monitor) Observe(now time.Time, s Sample) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.IsZero() || (!m.last.IsZero() && !now.After(m.last)) || s.Capacity <= 0 || s.Used < 0 || s.AckProgress < m.sample.AckProgress {
		m.failed = true
		m.notify()
		return errors.New("invalid sensor health sample")
	}
	wasHeld := m.held
	if !m.last.IsZero() && now.Sub(m.last) > SampleMaxAge {
		m.unknownTill = now.Add(60 * time.Second)
	}
	// ceil(4*capacity/5), without overflowing int64.
	threshold := s.Capacity/5*4 + (s.Capacity%5*4+4)/5
	if s.Used >= threshold {
		m.held = true
	}
	if s.GlobalMetrics {
		for i, known := range s.GlobalLoss.Known {
			if !known {
				m.unknownTill = now.Add(60 * time.Second)
				continue
			}
			if m.globalLoss.Known[i] {
				if s.GlobalLoss.Values[i] > m.globalLoss.Values[i] {
					m.held = true
				}
				if s.GlobalLoss.Values[i] < m.globalLoss.Values[i] {
					m.unknownTill = now.Add(60 * time.Second)
				}
			}
			m.globalLoss.Known[i], m.globalLoss.Values[i] = true, s.GlobalLoss.Values[i]
		}
	} else {
		if s.DropsKnown && m.dropsKnown {
			for i := range s.Drops {
				for j, value := range s.Drops[i] {
					if value > m.drops[i][j] {
						m.held = true
					}
					if value < m.drops[i][j] {
						// A reset is unknown loss, not a clean zero-loss window.
						m.unknownTill = now.Add(60 * time.Second)
					}
				}
			}
		} else if !m.last.IsZero() && (!s.DropsKnown || !m.dropsKnown) {
			m.unknownTill = now.Add(60 * time.Second)
		}
		// Unavailable metrics must not erase the last known cumulative baseline.
		// Compare the next known sample across the gap to detect hidden losses.
		if s.DropsKnown {
			m.dropsKnown, m.drops = true, s.Drops
		}
	}
	if !s.Pending {
		m.ackSince = time.Time{}
	} else if m.ackSince.IsZero() || s.AckProgress > m.sample.AckProgress {
		m.ackSince = now
	}
	m.last, m.sample = now, s
	m.stall(now)
	if m.held != wasHeld || !s.CaptureVerified || !s.lossKnown() {
		m.notify()
	}
	return nil
}

func (m *Monitor) stall(now time.Time) {
	if !m.ackSince.IsZero() && now.Sub(m.ackSince) >= 30*time.Second {
		m.held = true
	}
}

// DurabilityFailed is called synchronously on fsync/disk-full errors, including
// startup recovery errors, before a collection/delivery worker exits.
func (m *Monitor) DurabilityFailed() { m.fail(true) }

// RotationLost is called on EXPORT_ROTATION_LOSS. Gap persistence belongs to
// the observation pipeline; reporting this failure does not fabricate a gap ID.
func (m *Monitor) RotationLost() { m.fail(true) }

// WorkerStopped prevents healthy leases after a permanent acquisition/delivery
// failure. It does not misclassify parsing/authentication errors as disk loss.
func (m *Monitor) WorkerStopped() { m.fail(false) }

func (m *Monitor) fail(hold bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failed = true
	m.held = m.held || hold
	m.notify()
}

func (m *Monitor) State(now time.Time) State {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stall(now)
	fresh := !m.last.IsZero() && !now.Before(m.last) && now.Sub(m.last) <= SampleMaxAge
	return State{
		Healthy:   fresh && !m.failed && !m.held && m.sample.CaptureVerified && m.sample.lossKnown() && !now.Before(m.unknownTill),
		NeedsHold: m.held,
	}
}

// Holds stay latched for this monitor's lifetime. The release request contract
// is not implemented here. A heartbeat, empty spool, or restart cannot release
// an existing server hold; only the reason owner's authorized release can.

func (s Sample) lossKnown() bool {
	if s.GlobalMetrics {
		return s.GlobalLoss.complete()
	}
	return s.DropsKnown
}
