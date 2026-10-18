package healthreport

import (
	"testing"
	"time"
)

func goodSample() Sample { return Sample{CaptureVerified: true, DropsKnown: true, Capacity: 100} }

func TestMonitorEvidenceAndCapacity(t *testing.T) {
	now := time.Now()
	m := NewMonitor()
	if m.State(now).Healthy {
		t.Fatal("no evidence became healthy")
	}
	s := goodSample()
	s.Used = 79
	if err := m.Observe(now, s); err != nil {
		t.Fatal(err)
	}
	if !m.State(now).Healthy || m.State(now.Add(SampleMaxAge+1)).Healthy {
		t.Fatal("freshness not enforced")
	}
	s.Used = 80
	if err := m.Observe(now.Add(time.Second), s); err != nil {
		t.Fatal(err)
	}
	if state := m.State(now.Add(time.Second)); state.Healthy || !state.NeedsHold {
		t.Fatal(state)
	}
	s.Used = 0
	if err := m.Observe(now.Add(2*time.Second), s); err != nil {
		t.Fatal(err)
	}
	if !m.State(now.Add(2 * time.Second)).NeedsHold {
		t.Fatal("empty spool released a hold")
	}
}

func TestCapacityThresholdDoesNotOverflow(t *testing.T) {
	for _, capacity := range []int64{1, 2, 6, 100, 1<<63 - 1} {
		threshold := capacity/5*4 + (capacity%5*4+4)/5
		for _, offset := range []int64{-1, 0} {
			m, s, now := NewMonitor(), goodSample(), time.Now()
			s.Capacity, s.Used = capacity, threshold+offset
			if err := m.Observe(now, s); err != nil {
				t.Fatal(err)
			}
			if got := m.State(now).NeedsHold; got != (offset == 0) {
				t.Fatalf("capacity=%d used=%d hold=%v", capacity, s.Used, got)
			}
		}
	}
}

func TestEveryRequiredDropTriggersHold(t *testing.T) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 3; j++ {
			m, s, now := NewMonitor(), goodSample(), time.Now()
			if err := m.Observe(now, s); err != nil {
				t.Fatal(err)
			}
			s.Drops[i][j]++
			if err := m.Observe(now.Add(time.Second), s); err != nil {
				t.Fatal(err)
			}
			if !m.State(now.Add(time.Second)).NeedsHold {
				t.Fatalf("missed hook=%d metric=%d", i, j)
			}
		}
	}
}

func TestResetMissingAndSamplingGapAreUnknown(t *testing.T) {
	for _, cause := range []string{"reset", "missing", "gap"} {
		t.Run(cause, func(t *testing.T) {
			m, s, now := NewMonitor(), goodSample(), time.Now()
			s.Drops[0][0] = 10
			if err := m.Observe(now, s); err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Second)
			switch cause {
			case "reset":
				s.Drops[0][0] = 0
			case "missing":
				s.DropsKnown = false
			case "gap":
				now = now.Add(10 * time.Second)
			}
			if err := m.Observe(now, s); err != nil {
				t.Fatal(err)
			}
			if state := m.State(now); state.Healthy || state.NeedsHold {
				t.Fatal(state)
			}
			s.DropsKnown = true
			for n := 1; n <= 62; n++ {
				now = now.Add(time.Second)
				if err := m.Observe(now, s); err != nil {
					t.Fatal(err)
				}
				if n < 60 && m.State(now).Healthy {
					t.Fatal("unknown window cleared early")
				}
			}
			if !m.State(now).Healthy {
				t.Fatal("fresh known evidence never recovered")
			}
		})
	}
}

func TestACKStallRequiresBacklogAndDurableProgress(t *testing.T) {
	m, s, now := NewMonitor(), goodSample(), time.Now()
	if err := m.Observe(now, s); err != nil {
		t.Fatal(err)
	}
	if m.State(now.Add(time.Hour)).NeedsHold {
		t.Fatal("idle became ACK stall")
	}
	s.Pending = true
	for second := 1; second <= 60; second++ {
		if second == 30 {
			s.AckProgress = 1
		}
		at := now.Add(time.Duration(second) * time.Second)
		if err := m.Observe(at, s); err != nil {
			t.Fatal(err)
		}
		if got := m.State(at).NeedsHold; got != (second == 60) {
			t.Fatalf("second=%d hold=%v", second, got)
		}
	}
	// Timer path also detects a stuck delivery/sampling loop.
	m, s = NewMonitor(), goodSample()
	s.Pending = true
	if err := m.Observe(now, s); err != nil {
		t.Fatal(err)
	}
	if m.State(now.Add(30*time.Second-time.Nanosecond)).NeedsHold || !m.State(now.Add(30*time.Second)).NeedsHold {
		t.Fatal("30 second boundary")
	}
}

func TestInvalidInputAndWorkerFailureCannotReportHealthy(t *testing.T) {
	for _, kind := range []string{"clock", "capacity", "progress", "disk", "rotation", "worker"} {
		t.Run(kind, func(t *testing.T) {
			m, s, now := NewMonitor(), goodSample(), time.Now()
			s.AckProgress = 10
			if err := m.Observe(now, s); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "disk":
				m.DurabilityFailed()
			case "rotation":
				m.RotationLost()
			case "worker":
				m.WorkerStopped()
			default:
				at := now.Add(time.Second)
				if kind == "clock" {
					at = now
				}
				if kind == "capacity" {
					s.Capacity = 0
				}
				if kind == "progress" {
					s.AckProgress = 9
				}
				if m.Observe(at, s) == nil {
					t.Fatal("accepted invalid snapshot")
				}
			}
			if m.State(now).Healthy {
				t.Fatal("failed monitor healthy")
			}
			if m.State(now).NeedsHold != (kind == "disk" || kind == "rotation") {
				t.Fatal("wrong hold classification")
			}
		})
	}
}

func TestDropIncreaseAcrossUnknownSampleStillHolds(t *testing.T) {
	for i := range 4 {
		for j := range 3 {
			m, s, now := NewMonitor(), goodSample(), time.Now()
			s.Drops[i][j] = 10
			if err := m.Observe(now, s); err != nil {
				t.Fatal(err)
			}
			missing := goodSample()
			missing.DropsKnown = false
			if err := m.Observe(now.Add(time.Second), missing); err != nil {
				t.Fatal(err)
			}
			if m.State(now.Add(time.Second)).NeedsHold {
				t.Fatal("unknown metrics fabricated a loss")
			}
			s.Drops[i][j] = 15
			if err := m.Observe(now.Add(2*time.Second), s); err != nil {
				t.Fatal(err)
			}
			if !m.State(now.Add(2 * time.Second)).NeedsHold {
				t.Fatalf("lost counter increase across missing sample: %d/%d", i, j)
			}
		}
	}
}
