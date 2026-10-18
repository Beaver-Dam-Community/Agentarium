package healthreport

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/acquire"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

type lossFixture struct {
	value GlobalLoss
	err   error
}

func (l lossFixture) Scrape(context.Context) (GlobalLoss, error) { return l.value, l.err }

type captureFunc func(context.Context) (bool, error)

func (f captureFunc) VerifyCapture(c context.Context) (bool, error) { return f(c) }
func zeroLoss() lossFixture {
	return lossFixture{value: GlobalLoss{Known: [4]bool{true, true, true, true}}}
}
func openHealthWAL(t *testing.T, dir, epoch string) *wal.Journal {
	t.Helper()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	j, e := wal.Open(dir, epoch, 0)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { j.Close() })
	return j
}
func healthRecord(epoch string, seq uint64) ([]byte, error) {
	return json.Marshal(map[string]any{"source_epoch": epoch, "source_sequence": seq})
}
func TestSamplerRealWALReplayAckAndCaptureGate(t *testing.T) {
	dir := t.TempDir()
	j := openHealthWAL(t, dir, "old")
	if _, e := j.Append(healthRecord, wal.Checkpoint{}); e != nil {
		t.Fatal(e)
	}
	j.Close()
	j = openHealthWAL(t, dir, "new")
	if _, e := j.Append(healthRecord, wal.Checkpoint{}); e != nil {
		t.Fatal(e)
	}
	m := NewMonitor()
	s, e := NewSampler(j, zeroLoss(), nil, m)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.Sample(context.Background()); e != nil {
		t.Fatal(e)
	}
	if m.State(time.Now()).Healthy || !m.sample.Pending || m.sample.AckProgress != 0 {
		t.Fatal("replay or missing capture incorrectly represented", m.sample)
	}
	s.capture = captureFunc(func(context.Context) (bool, error) { return true, nil })
	if e := j.Ack("new", 1); e != nil {
		t.Fatal(e)
	}
	if e := s.Sample(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !m.sample.Pending || m.sample.AckProgress != 1 {
		t.Fatal("new epoch ACK hid old replay", m.sample)
	}
	if e := j.Ack("old", 1); e != nil {
		t.Fatal(e)
	}
	if e := s.Sample(context.Background()); e != nil {
		t.Fatal(e)
	}
	if m.sample.Pending || m.sample.AckProgress != 2 || !m.State(time.Now()).Healthy {
		t.Fatal(m.sample)
	}
	sink := &fakeSink{}
	r := reporter(t, m, sink)
	if e := r.Report(context.Background(), time.Now()); e != nil {
		t.Fatal(e)
	}
	if sink.leases[0].ObservedState != "healthy" {
		t.Fatal(sink.leases)
	}
	s.capture = captureFunc(func(context.Context) (bool, error) { return false, nil })
	if e := s.Sample(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := r.Report(context.Background(), time.Now()); e != nil {
		t.Fatal(e)
	}
	if sink.leases[1].ObservedState != "unhealthy" || len(sink.holds) != 0 {
		t.Fatal("failed capture fabricated sensor_degraded; probe hold belongs to TASK10")
	}
	j.Close()
	if e := s.Sample(context.Background()); e == nil {
		t.Fatal("closed WAL accepted")
	}
	if e := r.Report(context.Background(), time.Now()); e != nil {
		t.Fatal(e)
	}
	if len(sink.holds) != 1 {
		t.Fatal("unavailable WAL did not hold")
	}
}
func TestFilteredInputIsNotAckProgressOrCaptureEvidence(t *testing.T) {
	j := openHealthWAL(t, t.TempDir(), "epoch")
	live := filepath.Join(t.TempDir(), "tetragon.log")
	if e := os.WriteFile(live, []byte("{}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	collector, e := acquire.New(acquire.Config{Journal: j, LiveFile: live, MaxFiles: 2, MaxLineBytes: 1024, Normalize: func(context.Context, []byte) (acquire.Prepared, error) { return acquire.Prepared{Excluded: true}, nil }})
	if e != nil {
		t.Fatal(e)
	}
	result, e := collector.Step(context.Background())
	if e != nil || !result.Filtered {
		t.Fatal(result, e)
	}
	m := NewMonitor()
	s, _ := NewSampler(j, zeroLoss(), nil, m)
	if e := s.Sample(context.Background()); e != nil {
		t.Fatal(e)
	}
	if m.sample.Pending || m.sample.AckProgress != 0 || m.State(time.Now()).Healthy {
		t.Fatal("policy filtering supplied fabricated evidence", m.sample)
	}
	if records, e := j.Pending(); e != nil || len(records) != 0 {
		t.Fatal(records, e)
	}
}
func TestSamplerDoesNotRefreshSlowOrFailedEvidence(t *testing.T) {
	j := openHealthWAL(t, t.TempDir(), "epoch")
	m := NewMonitor()
	s, _ := NewSampler(j, zeroLoss(), captureFunc(func(ctx context.Context) (bool, error) { <-ctx.Done(); return true, nil }), m)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e := s.Sample(ctx); e == nil {
		t.Fatal("late evidence accepted")
	}
	if m.State(time.Now()).Healthy {
		t.Fatal("canceled evidence rejuvenated")
	}
	s.capture = captureFunc(func(context.Context) (bool, error) { return true, errors.New("private details") })
	if e := s.Sample(context.Background()); e == nil || e.Error() != "capture or metrics verification unavailable" {
		t.Fatal(e)
	}
	if m.State(time.Now()).Healthy {
		t.Fatal("failed verifier accepted")
	}
}

func TestFailedVerifierDoesNotHideKnownDrop(t *testing.T) {
	j := openHealthWAL(t, t.TempDir(), "epoch")
	m := NewMonitor()
	s, _ := NewSampler(j, zeroLoss(), captureFunc(func(context.Context) (bool, error) { return true, nil }), m)
	if e := s.Sample(context.Background()); e != nil {
		t.Fatal(e)
	}
	loss := zeroLoss()
	loss.value.Values[0] = 1
	s.loss = loss
	s.capture = captureFunc(func(ctx context.Context) (bool, error) { <-ctx.Done(); return false, ctx.Err() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e := s.Sample(ctx); e == nil {
		t.Fatal("lost verifier failure")
	}
	if state := m.State(time.Now()); state.Healthy || !state.NeedsHold {
		t.Fatal("known loss hidden by verifier timeout", state)
	}
}
