package probe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

const (
	testNode = "6f1c2b8e-1d2a-4c3b-9e8f-0a1b2c3d4e5f"
	testBoot = "0b8f3a52-7c1d-4e9a-8f6b-2d3c4e5f6a7b"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// stepClock advances by exactly the waited duration, so Probe is
// deterministic.
type stepClock struct{ now time.Time }

func (c *stepClock) Now() time.Time { return c.now }
func (c *stepClock) After(d time.Duration) <-chan time.Time {
	c.now = c.now.Add(d)
	ch := make(chan time.Time, 1)
	ch <- c.now
	return ch
}

type sent struct {
	at  time.Time
	res Result
}

func probeRunner(c *stepClock, stimulus error, answers ...int) (*Runner, *[]sent) {
	var log []sent
	i := 0
	r := &Runner{NodeUID: testNode, BootID: testBoot, Log: quiet, Now: c.Now, After: c.After,
		Stimuli: map[string]Stimulus{"process": func(context.Context) error { return stimulus }},
		Send: func(_ context.Context, res Result) (int, error) {
			log = append(log, sent{c.now, res})
			status := answers[min(i, len(answers)-1)]
			i++
			if status == 0 {
				return 0, errors.New("connection refused")
			}
			return status, nil
		}}
	return r, &log
}

func TestProbeJudgesAfterDelayAndReportsPass(t *testing.T) {
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	c := &stepClock{now: start}
	r, log := probeRunner(c, nil, 201)
	res, status := r.Probe(context.Background(), "process")
	if status != 201 || len(*log) != 1 {
		t.Fatalf("status %d sends %d", status, len(*log))
	}
	got := (*log)[0]
	if !got.at.Equal(start.Add(JudgeDelay)) {
		t.Fatalf("reported at +%s, want +25s", got.at.Sub(start))
	}
	want := Result{ProbeKind: "process", NodeUID: testNode, BootID: testBoot, StimulusAt: start, Outcome: "pass",
		EvidenceRefs: []string{"probe_stimulus:process:2026-10-18T12:00:00Z"}}
	if res.Outcome != "pass" || got.res.ProbeKind != want.ProbeKind || !got.res.StimulusAt.Equal(start) || !slices.Equal(got.res.EvidenceRefs, want.EvidenceRefs) {
		t.Fatalf("%+v", got.res)
	}
}

// 409 is "evidence not committed yet": the same stimulus_at is repeated every
// 3s while control-health still accepts its age, then the runner reports fail.
func TestProbeRetriesMissingEvidenceThenFails(t *testing.T) {
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	c := &stepClock{now: start}
	r, log := probeRunner(c, nil, 409, 409, 409, 409, 409, 201)
	res, status := r.Probe(context.Background(), "process")
	var offsets []time.Duration
	for _, s := range *log {
		offsets = append(offsets, s.at.Sub(start))
		if !s.res.StimulusAt.Equal(start) {
			t.Fatalf("stimulus_at changed on retry: %s", s.res.StimulusAt)
		}
	}
	want := []time.Duration{25 * time.Second, 28 * time.Second, 31 * time.Second, 34 * time.Second, 37 * time.Second, 37 * time.Second}
	if !slices.Equal(offsets, want) {
		t.Fatalf("report times %v, want %v", offsets, want)
	}
	outcomes := []string{}
	for _, s := range *log {
		outcomes = append(outcomes, s.res.Outcome)
	}
	if !slices.Equal(outcomes, []string{"pass", "pass", "pass", "pass", "pass", "fail"}) || res.Outcome != "fail" || status != 201 {
		t.Fatalf("outcomes %v final %s %d", outcomes, res.Outcome, status)
	}
	if last := (*log)[len(*log)-2].at.Sub(start); last > PassDeadline {
		t.Fatalf("pass sent at +%s, after the 38s bound", last)
	}
}

func TestProbeStimulusFailureReportsFailOnce(t *testing.T) {
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	c := &stepClock{now: start}
	r, log := probeRunner(c, errors.New("dial refused"), 201)
	res, _ := r.Probe(context.Background(), "process")
	if len(*log) != 1 || res.Outcome != "fail" || !(*log)[0].at.Equal(start.Add(JudgeDelay)) {
		t.Fatalf("%+v", *log)
	}
}

func TestProbeTransientAndRejectedAnswers(t *testing.T) {
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	// Unavailable control-health: retry, never turn a pass into a fail.
	c := &stepClock{now: start}
	r, log := probeRunner(c, nil, 503, 0, 503, 503, 503, 503)
	res, status := r.Probe(context.Background(), "process")
	if len(*log) != 5 || res.Outcome != "pass" || status != 503 {
		t.Fatalf("sends %d outcome %s status %d", len(*log), res.Outcome, status)
	}
	// Rejections are configuration errors: no retry.
	for _, code := range []int{401, 403, 422} {
		c := &stepClock{now: start}
		r, log := probeRunner(c, nil, code)
		if _, status := r.Probe(context.Background(), "process"); status != code || len(*log) != 1 {
			t.Fatalf("%d: sends %d", code, len(*log))
		}
	}
	// A fail that meets 409 (for example an unknown node boot) is not repeated.
	c = &stepClock{now: start}
	r, log = probeRunner(c, errors.New("x"), 409)
	if _, status := r.Probe(context.Background(), "process"); status != 409 || len(*log) != 1 {
		t.Fatalf("fail retried: %d", len(*log))
	}
}

// scaledClock runs virtual time 100x faster than real time, so Run's
// goroutines share one consistent clock.
type scaledClock struct {
	base, real time.Time
}

const scale = 100

func (c scaledClock) Now() time.Time {
	return c.base.Add(time.Since(c.real) * scale)
}
func (c scaledClock) After(d time.Duration) <-chan time.Time { return time.After(d / scale) }

// Cycles are anchored to the first one: stimulus_at of a kind advances by
// 60s per cycle even when a stimulus is slow, so consecutive passes fall in
// the 58-62s window control-health counts.
func TestRunSchedulesEveryPeriodPerKind(t *testing.T) {
	clock := scaledClock{base: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC), real: time.Now()}
	var mu sync.Mutex
	stimuli := map[string][]time.Time{}
	reports := map[string][]Result{}
	slow := func(kind string, d time.Duration) Stimulus {
		return func(context.Context) error {
			mu.Lock()
			stimuli[kind] = append(stimuli[kind], clock.Now())
			mu.Unlock()
			<-clock.After(d)
			return nil
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runner{NodeUID: testNode, BootID: testBoot, Log: quiet, Now: clock.Now, After: clock.After,
		Stimuli: map[string]Stimulus{"process": slow("process", 0), "tcp": slow("tcp", 3*time.Second), "file": slow("file", time.Second)},
		Send: func(_ context.Context, res Result) (int, error) {
			mu.Lock()
			reports[res.ProbeKind] = append(reports[res.ProbeKind], res)
			mu.Unlock()
			return 201, nil
		}}
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	// Three cycles start at 0s, 60s and 120s; stop at 140s, before the
	// third cycle is judged (145s).
	time.Sleep(140 * time.Second / scale)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	for _, kind := range Kinds {
		at := stimuli[kind]
		if len(at) != 3 {
			t.Fatalf("%s: %d stimuli", kind, len(at))
		}
		for i := 1; i < len(at); i++ {
			if gap := at[i].Sub(at[i-1]); gap < 59*time.Second || gap > 61*time.Second {
				t.Fatalf("%s: stimuli %s apart", kind, gap)
			}
		}
		if len(reports[kind]) != 2 {
			t.Fatalf("%s: %d reports before cancel", kind, len(reports[kind]))
		}
	}
}

// The body is exactly the COMMON probe-results wire for a node answer probe.
func TestSenderWireFormat(t *testing.T) {
	var got map[string]json.RawMessage
	var path, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ctype = r.URL.Path, r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"probe_result_id":"11111111-1111-4111-8111-111111111111"}`))
	}))
	defer srv.Close()
	at := time.Date(2026, 10, 18, 12, 0, 0, 123000000, time.UTC)
	res := Result{ProbeKind: "tcp", NodeUID: testNode, BootID: testBoot, StimulusAt: at, Outcome: "pass", EvidenceRefs: []string{StimulusRef("tcp", at)}}
	status, err := Sender{URL: srv.URL, Path: RelayPath, Client: srv.Client()}.Send(context.Background(), res)
	if err != nil || status != 201 || path != RelayPath || ctype != "application/json" {
		t.Fatalf("%d %v %s %s", status, err, path, ctype)
	}
	keys := []string{}
	for k := range got {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"boot_id", "evidence_refs", "node_uid", "outcome", "probe_kind", "stimulus_at"}) {
		t.Fatalf("wire keys %v", keys)
	}
	if string(got["stimulus_at"]) != `"2026-10-18T12:00:00.123Z"` || string(got["evidence_refs"]) != `["probe_stimulus:tcp:2026-10-18T12:00:00.123Z"]` {
		t.Fatalf("%s %s", got["stimulus_at"], got["evidence_refs"])
	}
	// A 2xx other than 201 or a missing probe_result_id is not an ack.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) }))
	defer bad.Close()
	if _, err := (Sender{URL: bad.URL, Path: DirectPath, Client: bad.Client()}).Send(context.Background(), res); err == nil {
		t.Fatal("accepted an empty acknowledgement")
	}
}
