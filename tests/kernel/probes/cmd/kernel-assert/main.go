// Command kernel-assert checks one kernel-stimulus run against observed
// KernelEvents and writes a COMMON result record (TASK-09 7, 8).
//
//	kernel-assert --stimulus stimulus.jsonl --pod-uid <uid> --node-uid <uid> \
//	    [--wal wal.ndjson] [--dsn postgres://...] --run-id <id> --out <dir>
//
// --wal is `exporter inspect-wal` output (fsynced, not yet acknowledged
// events; identity and record_digest are recomputed). --dsn reads stored rows
// from audit.kernel_events read-only. At least one source is required. Exit
// status 0 means every expected case passed; 1 means failed; 2 means the run
// could not be evaluated.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/tests/kernel/probes"
	"github.com/jackc/pgx/v5"
)

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kernel-assert:", err)
	}
	os.Exit(code)
}

func run() (int, error) {
	stimulus := flag.String("stimulus", "", "kernel-stimulus log")
	wal := flag.String("wal", "", "exporter inspect-wal NDJSON")
	dsn := flag.String("dsn", os.Getenv("KERNEL_PROBES_DSN"), "read-only audit DB DSN")
	podUID := flag.String("pod-uid", "", "stimulus Pod UID")
	nodeUID := flag.String("node-uid", "", "Node metadata.uid of the stimulus node")
	runID := flag.String("run-id", "", "result run_id")
	out := flag.String("out", "", "result directory")
	flag.Parse()
	if *stimulus == "" || *podUID == "" || *runID == "" || *out == "" || (*wal == "" && *dsn == "") || (*dsn != "" && *nodeUID == "") {
		return 2, errors.New("--stimulus, --pod-uid, --run-id, --out and --wal or --dsn (with --node-uid) are required")
	}
	sf, err := os.Open(*stimulus)
	if err != nil {
		return 2, err
	}
	stimuli, err := probes.ReadStimuli(sf)
	sf.Close()
	if err != nil {
		return 2, err
	}
	var walEvents, stored []probes.Event
	sources := []string{}
	if *wal != "" {
		f, err := os.Open(*wal)
		if err != nil {
			return 2, err
		}
		walEvents, err = probes.ReadEvents(f, true)
		f.Close()
		if err != nil {
			return 2, err
		}
		sources = append(sources, "wal")
	}
	if *dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, *dsn)
		if err != nil {
			return 2, errors.New("audit DB unavailable")
		}
		defer conn.Close(ctx)
		from, to := window(stimuli)
		stored, err = probes.QueryEvents(ctx, conn, *nodeUID, from, to)
		if err != nil {
			return 2, err
		}
		sources = append(sources, "audit.kernel_events")
	}
	// Only WAL records carry exact bytes; verify those, compare stored digests.
	report, err := probes.Evaluate(probes.Input{Stimuli: stimuli, Events: walEvents, PodUID: *podUID, VerifyRaw: true})
	if err != nil {
		return 2, err
	}
	merged, conflicts := probes.Merge(walEvents, stored)
	final, err := probes.Evaluate(probes.Input{Stimuli: stimuli, Events: merged, PodUID: *podUID})
	if err != nil {
		return 2, err
	}
	final.IntegrityErr = append(report.IntegrityErr, conflicts...)
	if err := write(*out, *runID, sources, len(walEvents), len(stored), final); err != nil {
		return 2, err
	}
	for _, c := range final.Cases {
		fmt.Printf("%-28s %-8s expected=%d observed=%d\n", c.ID, c.Status, c.Expected, c.Observed)
	}
	if !final.Passed() {
		return 1, nil
	}
	return 0, nil
}

func window(stimuli []probes.Stimulus) (time.Time, time.Time) {
	var from, to time.Time
	for _, s := range stimuli {
		t, err := time.Parse(time.RFC3339Nano, s.Time)
		if err != nil {
			continue
		}
		if from.IsZero() || t.Before(from) {
			from = t
		}
		if t.After(to) {
			to = t
		}
	}
	return from.Add(-5 * time.Second), to.Add(60 * time.Second)
}

func write(dir, runID string, sources []string, walN, storedN int, r probes.Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	passed, failed, notRun := 0, 0, 0
	f, err := os.Create(filepath.Join(dir, "observed.jsonl"))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, c := range r.Cases {
		switch c.Status {
		case "passed":
			passed++
		case "failed":
			failed++
		default:
			notRun++
		}
		if err := enc.Encode(c); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	status := "passed"
	if !r.Passed() {
		status = "failed"
	}
	summary := map[string]any{
		"task_id": "TASK-09", "run_id": runID, "run_kind": "kernel_ground_truth_observation", "status": status,
		"expected_cases": len(r.Cases) - notRun, "observed_cases": passed + failed, "passed": passed, "failed": failed, "unknown": 0, "not_run": notRun,
		"event_sources": sources, "wal_events": walN, "stored_events": storedN, "events_in_window": r.Events,
		"integrity_errors": r.IntegrityErr, "evidence_refs": []string{"observed.jsonl", "raw/"},
	}
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "summary.json"), append(b, '\n'), 0o644)
}
