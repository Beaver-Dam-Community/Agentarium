package risk

import (
	"testing"
	"time"
)

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	workload := "agent-exec/runtime"
	w := &workload
	flags := func(v int64) *int64 { return &v }
	cfg := Config{ProtectedPaths: []string{"/work/protected-fixture"}, FlagsVerified: true,
		ContainerRoots: map[string]string{RootKey("n", "b", "c"): "root"}, WorkerRoots: map[string]bool{"worker": true}}
	exec := func(id, execID, parent, container string, wl *string) Event {
		return Event{ID: id, EventType: "process_exec", NodeUID: "n", BootID: "b", ContainerID: container, ProcessExecID: execID, ParentExecID: parent, SourceTime: now, WorkloadID: wl}
	}
	events := []Event{
		{ID: "connect-out", EventType: "tcp_connect", NodeUID: "n", BootID: "b", ContainerID: "c", Established: true, WorkloadID: w},
		{ID: "connect-blocked", EventType: "tcp_connect", NodeUID: "n", BootID: "b", ContainerID: "c", Established: false, WorkloadID: w},
		{ID: "connect-allowed", EventType: "tcp_connect", NodeUID: "n", BootID: "b", ContainerID: "c", Established: true, DestinationAllowed: true, WorkloadID: w},
		{ID: "connect-confirmed", EventType: "tcp_connect", NodeUID: "n", BootID: "b", ContainerID: "c", Established: true, Confirmed: true, WorkloadID: w},
		{ID: "connect-unmapped", EventType: "tcp_connect", NodeUID: "n", BootID: "b", ContainerID: "x", Established: true},
		{ID: "write", EventType: "openat", Path: "/work/protected-fixture", Flags: flags(0x241), WorkloadID: w},
		{ID: "read", EventType: "file_open", Path: "/work/protected-fixture", Flags: flags(0), WorkloadID: w},
		{ID: "other-path", EventType: "openat", Path: "/tmp/x", Flags: flags(1), WorkloadID: w},
		exec("root-exec", "root", "", "c", w),
		exec("child", "child", "root", "c", w),
		exec("grandchild", "grandchild", "child", "c", w),
		exec("worker-child", "wc", "worker", "c", w),
		exec("host-shim", "shim", "", "", nil),
		exec("injected", "inj", "shim", "c", w),
		exec("orphan", "orph", "missing-parent", "c", w),
	}
	decisions, candidates := Evaluate(events, cfg)
	want := map[string]string{"connect-out": DetailConnect, "write": DetailWrite, "injected": DetailExec}
	if len(decisions) != len(want) {
		t.Fatalf("decisions %+v", decisions)
	}
	for _, d := range decisions {
		if want[d.KernelEventID] != d.Detail || d.WorkloadID != workload {
			t.Fatalf("decision %+v", d)
		}
	}
	if len(candidates) != 1 || candidates[0].KernelEventID != "orphan" {
		t.Fatalf("candidates %+v", candidates)
	}
	// Until TASK-09 Q0 verifies open flags, protected-path opens are marked only.
	cfg.FlagsVerified = false
	decisions, candidates = Evaluate(events, cfg)
	for _, d := range decisions {
		if d.Detail == DetailWrite {
			t.Fatal("unverified flags created a write hold")
		}
	}
	marked := 0
	for _, c := range candidates {
		if c.Detail == DetailWrite {
			marked++
		}
	}
	if marked != 2 {
		t.Fatalf("protected path candidates %d", marked)
	}
	// A container without a known start process cannot judge lineage.
	cfg.ContainerRoots = map[string]string{}
	decisions, _ = Evaluate(events, cfg)
	for _, d := range decisions {
		if d.Detail == DetailExec {
			t.Fatal("exec judged without a container root")
		}
	}
}

func TestStartsContainer(t *testing.T) {
	start := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	for offset, want := range map[time.Duration]bool{-3 * time.Second: false, -2 * time.Second: true, 0: true, 5 * time.Second: true, 6 * time.Second: false, 30 * time.Minute: false} {
		if StartsContainer(start, start.Add(offset)) != want {
			t.Errorf("exec at %v after start: want %v", offset, want)
		}
	}
}
