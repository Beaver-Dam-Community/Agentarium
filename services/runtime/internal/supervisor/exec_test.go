package supervisor

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/procinfo"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/spawn"
)

// buildWorker compiles cmd/worker into a temp dir.
func buildWorker(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available")
	}
	out := filepath.Join(t.TempDir(), "agent-worker")
	cmd := exec.Command(goBin, "build", "-o", out, "../../cmd/worker")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build worker: %v\n%s", err, b)
	}
	return out
}

// TestRealWorkerExec runs the real worker binary through spawn.Exec. On
// Linux the worker applies the seccomp profile and the full flow completes;
// the registration hook checks that the worker is a direct child of this
// process, that its executable is the worker binary itself (one exec, no
// wrapper) and that the hints match /proc. Elsewhere the controls cannot
// be applied and nothing may be registered.
func TestRealWorkerExec(t *testing.T) {
	path := buildWorker(t)
	h := newHarness(t)
	h.s.Spawn = spawn.Exec{Path: path, ScratchRoot: t.TempDir()}
	if runtime.GOOS != "linux" {
		out, err := h.run(t)
		if err == nil || !strings.HasPrefix(out.Error, ErrIsolation) || len(h.g.registrations) != 0 {
			t.Fatalf("err %v outcome %+v registrations %d", err, out, len(h.g.registrations))
		}
		return
	}
	h.s.Cfg.Hint = func(pid int) (procinfo.Hint, error) { return procinfo.Of("/proc", pid) }
	h.s.Cfg.SupervisorPID = os.Getpid()
	var checked bool
	h.g.onRegister = func(body map[string]json.RawMessage) {
		var wh, sh procinfo.Hint
		_ = json.Unmarshal(body["worker_process_hint"], &wh)
		_ = json.Unmarshal(body["supervisor_process_hint"], &sh)
		pid := int(wh.LocalPID)
		status, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
		if err != nil {
			t.Errorf("worker status: %v", err)
			return
		}
		if !strings.Contains(string(status), "\nPPid:\t"+strconv.Itoa(os.Getpid())+"\n") {
			t.Errorf("worker parent is not the supervisor:\n%s", status)
		}
		// exe is unreadable for a non-root caller once the worker is
		// non-dumpable; comm (from the exec'd file name) is always readable.
		if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil && exe != path {
			t.Errorf("worker exe %q, want %q", exe, path)
		}
		stat, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if !strings.Contains(string(stat), " (agent-worker) ") {
			t.Errorf("worker comm: %s", stat)
		}
		if cur, _ := procinfo.Of("/proc", pid); cur != wh {
			t.Errorf("hint %+v, /proc %+v", wh, cur)
		}
		if sh.LocalPID != int64(os.Getpid()) || sh.PIDNSInode != wh.PIDNSInode {
			t.Errorf("supervisor hint %+v worker %+v", sh, wh)
		}
		var controls map[string]any
		if json.Unmarshal(body["controls_report"], &controls) != nil || controls["profile"] != "process_baseline" {
			t.Errorf("controls %s", body["controls_report"])
		}
		checked = true
	}
	out, err := h.run(t)
	if err != nil {
		t.Fatalf("run: %v (%+v)", err, out)
	}
	if !checked || len(h.g.registrations) != 1 || out.ExecutionState != "effect_verified" {
		t.Fatalf("checked %v registrations %d outcome %+v", checked, len(h.g.registrations), out)
	}
}
