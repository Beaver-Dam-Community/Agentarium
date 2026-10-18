//go:build linux && (amd64 || arm64)

package isolation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The filter is permanent, so it is applied in a child copy of the test
// binary, never in the test process itself.
func TestMain(m *testing.M) {
	if mode := os.Getenv("ISOLATION_SUPERVISOR_TEST"); mode != "" {
		if err := supervisorMemoryChild(mode); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv("ISOLATION_APPLY_CHILD") == "1" {
		rep, err := Apply()
		out := map[string]any{"report": rep}
		if err != nil {
			out["error"] = err.Error()
		}
		e := syscall.Exec("/bin/true", []string{"true"}, nil)
		out["execve"] = errors.Is(e, syscall.EPERM)
		_, _, ce := unix.RawSyscall(unix.SYS_CLONE3, 0, 0, 0)
		out["clone3_enosys"] = ce == unix.ENOSYS
		_ = json.NewEncoder(os.Stdout).Encode(out)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestApplyInChild(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = []string{"ISOLATION_APPLY_CHILD=1"}
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("child: %v %s", err, raw)
	}
	var out struct {
		Report       Report `json:"report"`
		Error        string `json:"error"`
		Execve       bool   `json:"execve"`
		Clone3ENOSYS bool   `json:"clone3_enosys"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("child output %q: %v", raw, err)
	}
	if out.Error != "" {
		t.Fatalf("Apply: %s", out.Error)
	}
	if !out.Execve || !out.Clone3ENOSYS {
		t.Fatalf("execve refused %v, clone3 ENOSYS %v", out.Execve, out.Clone3ENOSYS)
	}
	for _, k := range []string{"dumpable", "no_new_privs", "rlimit_core", "prctl_set_dumpable", "kcmp", "ptrace", "unshare"} {
		if out.Report.Checks[k] == "" {
			t.Errorf("check %s missing: %+v", k, out.Report.Checks)
		}
	}
}

func TestProgramCoversEveryDeniedSyscall(t *testing.T) {
	if _, err := program(); err != nil {
		t.Fatal(err)
	}
}
