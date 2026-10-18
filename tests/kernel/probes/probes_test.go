package probes

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/normalize"
)

const (
	q0Run      = "../../../evidence/gcp/runs/20261015-task01-q0-min-2/raw/"
	q0Node     = "gke-agentarium-prod-exec-pool-eaf0304a-x10z"
	q0PodUID   = "d7dafa84-b27f-4944-863f-e49e45c8d4a4"
	q0Cid      = "866bba3230f127c9fd2035b57c32fd234ff3c0e86c7cf2930d66e770216b3587"
	sensorSAN  = "spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon"
	fixtureNod = "30000000-0000-4000-8000-000000000001"
)

type resolver struct{}

func (resolver) Resolve(_ context.Context, q normalize.Query) (normalize.Resolution, error) {
	if q.EventType == "tcp_state" {
		return normalize.Resolution{Scope: normalize.Include, MetadataStatus: normalize.MetadataTupleScoped}, nil
	}
	return normalize.Resolution{Scope: normalize.Include, MetadataStatus: normalize.MetadataResolved, ContainerID: q0Cid, PodUID: q0PodUID}, nil
}

// q0Events turns the real Q0 Tetragon export into KernelEvent NDJSON with the
// production normalizer, exactly as the exporter WAL would hold it.
func q0Events(t *testing.T) []byte {
	t.Helper()
	n, err := normalize.New(normalize.Config{SensorID: sensorSAN, ExporterInstanceID: "40000000-0000-4000-8000-000000000002", NodeUID: fixtureNod, BootID: "6f1d3d1c-1f5e-4a1b-9c7c-0c4f7d9e2a11", NodeName: q0Node, SensorGeneration: 1, RuleHash: strings.Repeat("ab", 32), Coverage: "test", NormalizationVersion: "test", ProtectedPaths: []string{"/work/protected-fixture"}, Resolver: resolver{}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(q0Run + "run3-events.relevant.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out bytes.Buffer
	s := bufio.NewScanner(f)
	s.Buffer(nil, 1<<20)
	seq := uint64(0)
	for s.Scan() {
		p, err := n.Prepare(context.Background(), s.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if p.Excluded {
			continue
		}
		seq++
		b, err := p.Build("epoch_q0", seq)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(append(b, '\n'))
	}
	return out.Bytes()
}

func evaluate(t *testing.T, events []byte, podUID string, raw bool) Report {
	t.Helper()
	sf, err := os.Open(q0Run + "run3-stimuli.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer sf.Close()
	stimuli, err := ReadStimuli(sf)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := ReadEvents(bytes.NewReader(events), raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Evaluate(Input{Stimuli: stimuli, Events: evs, PodUID: podUID, VerifyRaw: raw})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func status(rep Report) map[string]string {
	m := map[string]string{}
	for _, c := range rep.Cases {
		m[c.ID] = c.Status
	}
	return m
}

func TestQ0EvidencePassesEveryObservedCase(t *testing.T) {
	rep := evaluate(t, q0Events(t), q0PodUID, true)
	want := map[string]string{
		"process_exec": "passed", "process_exit": "passed",
		"tcp_connect_attempt": "passed", "tcp_established_linked": "passed", "tcp_close_linked": "passed",
		"tcp_failed_attempt": "not_run", "tcp_failed_not_established": "not_run",
		"file_open_allowed": "passed", "openat_allowed": "passed", "openat_denied_eacces": "passed", "file_open_not_on_denied": "passed",
	}
	got := status(rep)
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s (%+v)", k, got[k], v, rep.Cases)
		}
	}
	if !rep.Passed() || rep.Events != 245 || len(rep.IntegrityErr) != 0 {
		t.Fatalf("report %+v", rep)
	}
}

func mutate(t *testing.T, events []byte, f func(map[string]any) bool) []byte {
	var out bytes.Buffer
	for _, line := range bytes.Split(bytes.TrimSpace(events), []byte("\n")) {
		var m map[string]any
		d := json.NewDecoder(bytes.NewReader(line))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			t.Fatal(err)
		}
		if !f(m) {
			continue
		}
		b, _ := json.Marshal(m)
		out.Write(append(b, '\n'))
	}
	return out.Bytes()
}

func TestMissingOrForgedObservationsFail(t *testing.T) {
	events := q0Events(t)
	noEstablished := mutate(t, events, func(m map[string]any) bool {
		return !(m["event_type"] == "tcp_state" && m["tcp_new_state"] == json.Number("1"))
	})
	if s := status(evaluate(t, noEstablished, q0PodUID, false)); s["tcp_established_linked"] != "failed" || s["tcp_connect_attempt"] != "passed" {
		t.Fatalf("missing ESTABLISHED must fail: %v", s)
	}
	noDenied := mutate(t, events, func(m map[string]any) bool {
		sa := m["safe_attributes"].(map[string]any)
		return !(m["event_type"] == "openat" && sa["return_errno"] != nil)
	})
	if s := status(evaluate(t, noDenied, q0PodUID, false)); s["openat_denied_eacces"] != "failed" {
		t.Fatalf("missing EACCES must fail: %v", s)
	}
	if rep := evaluate(t, events, "00000000-0000-4000-8000-000000000000", false); rep.Passed() {
		t.Fatal("events of another Pod must not satisfy the stimulus")
	}
	// Changing a field without recomputing record_digest is an integrity error.
	tampered := mutate(t, events, func(m map[string]any) bool {
		if m["event_type"] == "process_exec" {
			m["metadata_status"] = "tampered"
		}
		return true
	})
	if rep := evaluate(t, tampered, q0PodUID, true); rep.Passed() || len(rep.IntegrityErr) == 0 {
		t.Fatal("tampered record accepted")
	}
}

// The real stimulus binary produces records the checker parses, including a
// refused connect with a known attempted tuple.
func TestStimulusBinaryRecords(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("DAC denial needs a non-root user")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "kernel-stimulus")
	if out, err := exec.Command("go", "build", "-o", bin, "./cmd/kernel-stimulus").CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	l, err := netListen()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	closed, err := netListen()
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "STIMULUS_COUNT=3", "STIMULUS_TCP_OPEN="+l.Addr().String(), "STIMULUS_TCP_FAILED="+closedAddr, "STIMULUS_FIXTURE="+filepath.Join(dir, "protected-fixture"))
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(30*time.Second, func() { cmd.Process.Kill() })
	defer timer.Stop()
	var stdout bytes.Buffer
	sc := bufio.NewScanner(pipe)
	for sc.Scan() {
		stdout.Write(append(sc.Bytes(), '\n'))
		if strings.Contains(sc.Text(), `"kind":"done"`) {
			break
		}
	}
	cmd.Process.Signal(os.Interrupt)
	cmd.Wait()
	stimuli, err := ReadStimuli(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, s := range stimuli {
		kinds[s.Kind]++
		switch s.Kind {
		case "tcp":
			if !s.OK || s.Local == "" {
				t.Fatalf("open connect: %+v", s)
			}
		case "tcp_failed":
			if s.OK || s.Local == "" || !strings.Contains(s.Errno, "refused") {
				t.Fatalf("refused connect must keep its attempted tuple: %+v", s)
			}
		case "file_open_denied":
			if s.OK || !strings.Contains(s.Errno, "permission denied") {
				t.Fatalf("denied open: %+v", s)
			}
		}
	}
	for _, k := range []string{"process", "tcp", "tcp_failed", "file_open_allowed", "file_open_denied"} {
		if kinds[k] != 3 {
			t.Fatalf("%s: %d records (%v)", k, kinds[k], kinds)
		}
	}
	// With no kernel events every expected case fails rather than passing.
	rep, err := Evaluate(Input{Stimuli: stimuli, PodUID: q0PodUID})
	if err != nil || rep.Passed() {
		t.Fatalf("empty observation must fail: %+v %v", rep, err)
	}
}

func netListen() (net.Listener, error) { return net.Listen("tcp4", "127.0.0.1:0") }

// The kernel-assert command writes a COMMON result record and exits 0 only
// when every expected case passed.
func TestAssertCommandWritesResultRecord(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "kernel-assert")
	if out, err := exec.Command("go", "build", "-o", bin, "./cmd/kernel-assert").CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	events := q0Events(t)
	for _, tc := range []struct {
		name   string
		events []byte
		code   int
		status string
	}{
		{"complete", events, 0, "passed"},
		{"exec lost", mutate(t, events, func(m map[string]any) bool { return m["event_type"] != "process_exec" }), 1, "failed"},
	} {
		wal := filepath.Join(dir, tc.name+".ndjson")
		if err := os.WriteFile(wal, tc.events, 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, tc.name)
		cmd := exec.Command(bin, "--stimulus", q0Run+"run3-stimuli.jsonl", "--wal", wal, "--pod-uid", q0PodUID, "--run-id", "test-"+tc.name, "--out", out)
		output, _ := cmd.CombinedOutput()
		if cmd.ProcessState.ExitCode() != tc.code {
			t.Fatalf("%s: exit %d\n%s", tc.name, cmd.ProcessState.ExitCode(), output)
		}
		var summary map[string]any
		b, err := os.ReadFile(filepath.Join(out, "summary.json"))
		if err != nil || json.Unmarshal(b, &summary) != nil || summary["status"] != tc.status || summary["task_id"] != "TASK-09" || summary["wal_events"].(float64) == 0 {
			t.Fatalf("%s: summary %s %v", tc.name, b, err)
		}
	}
	if code := exec.Command(bin, "--stimulus", "x").Run(); code == nil {
		t.Fatal("missing inputs must not succeed")
	}
}

// A TCP stimulus whose local port was never bound is still expected (fails),
// and every passed case lists the matched source_event_ids.
func TestUnboundStimulusFailsAndCasesCarryEventIDs(t *testing.T) {
	events := q0Events(t)
	sf, err := os.Open(q0Run + "run3-stimuli.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	stimuli, err := ReadStimuli(sf)
	sf.Close()
	if err != nil {
		t.Fatal(err)
	}
	for i := range stimuli {
		if stimuli[i].Kind == "tcp" {
			stimuli[i].Local = ""
			break
		}
	}
	evs, _ := ReadEvents(bytes.NewReader(events), true)
	rep, err := Evaluate(Input{Stimuli: stimuli, Events: evs, PodUID: q0PodUID, VerifyRaw: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Cases {
		if c.ID == "tcp_connect_attempt" && (c.Status != "failed" || c.Expected != 30 || c.Observed != 29) {
			t.Fatalf("unbound stimulus must count as expected: %+v", c)
		}
		if c.Status == "passed" && len(c.EventIDs) != c.Observed {
			t.Fatalf("%s: event IDs %d != observed %d", c.ID, len(c.EventIDs), c.Observed)
		}
	}
}
