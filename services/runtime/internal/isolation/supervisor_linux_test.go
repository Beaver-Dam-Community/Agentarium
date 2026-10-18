//go:build linux && (amd64 || arm64)

package isolation

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Run in disposable processes: RLIMIT_CORE and worker seccomp are irreversible.
// The unprotected control proves that container/Yama restrictions alone do not
// explain a passing test. PR_SET_PTRACER_ANY relaxes Yama only in this fixture.
func TestSupervisorMemoryBoundary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run as an unprivileged UID with capabilities dropped; root can bypass procfs fd permissions")
	}
	for _, mode := range []string{"unprotected", "protected"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^$")
			cmd.Env = []string{"ISOLATION_SUPERVISOR_TEST=" + mode}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("supervisor fixture: %v\n%s", err, out)
			}
		})
	}
}

func supervisorMemoryChild(mode string) error {
	if mode == "worker" {
		return probeSupervisorMemory()
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		return err
	}
	// Kernels without Yama return EINVAL. The unprotected control below
	// still must read the marker; no denial is accepted as a passing control.
	if err := unix.Prctl(unix.PR_SET_PTRACER, ^uintptr(0), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
		return err
	}
	if mode == "protected" {
		if err := ProtectSupervisor(); err != nil {
			return err
		}
		d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || d != 0 {
			return fmt.Errorf("dumpable=%d: %v", d, err)
		}
		var rl unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil || rl.Cur != 0 || rl.Max != 0 {
			return fmt.Errorf("core limit=%+v: %v", rl, err)
		}
	}
	secret := []byte("test-only-supervisor-memory-marker")
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = []string{
		"ISOLATION_SUPERVISOR_TEST=worker",
		"PARENT_PROTECTED=" + strconv.FormatBool(mode == "protected"),
		"PARENT_ADDRESS=" + strconv.FormatUint(uint64(uintptr(unsafe.Pointer(&secret[0]))), 10),
	}
	out, err := cmd.CombinedOutput()
	runtime.KeepAlive(secret)
	if err != nil {
		return fmt.Errorf("worker probe: %w: %s", err, out)
	}
	return nil
}

func probeSupervisorMemory() error {
	if _, err := Apply(); err != nil {
		return err
	}
	protected := os.Getenv("PARENT_PROTECTED") == "true"
	base := fmt.Sprintf("/proc/%d/", os.Getppid())
	addr, err := strconv.ParseInt(os.Getenv("PARENT_ADDRESS"), 10, 64)
	if err != nil {
		return err
	}
	// The worker has the real process_baseline filter, including ptrace denial.
	// Opening procfs is still allowed; the supervisor's dumpable flag must block it.
	probes := map[string]func() error{
		"mem": func() error {
			f, err := os.Open(base + "mem")
			if err != nil {
				return err
			}
			defer f.Close()
			want := []byte("test-only-supervisor-memory-marker")
			got := make([]byte, len(want))
			if _, err := f.ReadAt(got, addr); err != nil {
				return err
			}
			if !bytes.Equal(got, want) {
				return errors.New("memory marker mismatch")
			}
			return nil
		},
		"environ": func() error { _, err := os.ReadFile(base + "environ"); return err },
		"fd":      func() error { _, err := os.ReadDir(base + "fd"); return err },
	}
	for name, probe := range probes {
		err := probe()
		if protected && !errors.Is(err, unix.EACCES) {
			return fmt.Errorf("%s: want EACCES, got %v", name, err)
		}
		if !protected && err != nil {
			return fmt.Errorf("%s: unprotected control failed: %w", name, err)
		}
	}
	return nil
}
