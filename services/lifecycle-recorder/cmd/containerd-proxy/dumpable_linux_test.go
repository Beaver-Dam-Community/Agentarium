//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNonDumpableSetsAndConfirms(t *testing.T) {
	if err := nonDumpable(); err != nil {
		t.Fatal(err)
	}
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || d != 0 {
		t.Fatalf("dumpable %d %v", d, err)
	}
}

func TestNonDumpableFailsClosed(t *testing.T) {
	origPrctl, origGet := prctl, getDumpable
	t.Cleanup(func() { prctl, getDumpable = origPrctl, origGet })

	prctl = func(int, uintptr, uintptr, uintptr, uintptr) error { return unix.EPERM }
	if err := nonDumpable(); !errors.Is(err, unix.EPERM) {
		t.Fatalf("prctl refused: got %v", err)
	}
	prctl = func(int, uintptr, uintptr, uintptr, uintptr) error { return nil }
	getDumpable = func() (int, error) { return 1, nil }
	if err := nonDumpable(); err == nil {
		t.Fatal("dumpable still 1 must fail")
	}
	getDumpable = func() (int, error) { return 0, unix.EINVAL }
	if err := nonDumpable(); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("PR_GET_DUMPABLE error: got %v", err)
	}
}

// TestProcRootDeniedWhenNonDumpable runs the helper below as a child of the
// same UID: after nonDumpable, the parent (without CAP_SYS_PTRACE, like the
// exporter) cannot follow /proc/<child>/root, fd or read environ.
func TestProcRootDeniedWhenNonDumpable(t *testing.T) {
	if os.Getenv(helperEnv) != "" {
		return
	}
	if hasCap(t, unix.CAP_SYS_PTRACE) {
		t.Skip("test process has CAP_SYS_PTRACE; run without it (docker default) to check the denial")
	}
	pid := startHelper(t, os.Args[0], "prctl")
	assertProcDenied(t, pid)
}

// TestNonDumpableFromExec checks the image setting: a binary the caller cannot
// read (mode 0111, UID 0 without CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH) is
// non-dumpable from execve, before any of its code runs. The helper here never
// calls prctl. The 0755 copy is the control: the same helper stays reachable.
func TestNonDumpableFromExec(t *testing.T) {
	if os.Getenv(helperEnv) != "" {
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs UID 0 like containerd-proxy and the exporter")
	}
	for _, c := range []int{unix.CAP_SYS_PTRACE, unix.CAP_DAC_OVERRIDE, unix.CAP_DAC_READ_SEARCH} {
		if hasCap(t, c) {
			t.Skipf("test process has capability %d; run with every capability dropped, like the Pod", c)
		}
	}
	if b, err := os.ReadFile("/proc/sys/fs/suid_dumpable"); err != nil || strings.TrimSpace(string(b)) == "1" {
		t.Skipf("fs.suid_dumpable is %q (%v); 1 keeps unreadable binaries dumpable", b, err)
	}
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, tc := range []struct {
		mode   os.FileMode
		denied bool
	}{{0o755, false}, {0o111, true}} {
		path := fmt.Sprintf("%s/proxy-%o", dir, tc.mode)
		if err := os.WriteFile(path, self, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		pid := startHelper(t, path, "exec")
		if tc.denied {
			assertProcDenied(t, pid)
		} else if _, err := os.Readlink("/proc/" + pid + "/root"); err != nil {
			t.Errorf("mode %o control: /proc/%s/root must be readable, got %v", tc.mode, pid, err)
		}
	}
}

const helperEnv = "CONTAINERD_PROXY_DUMPABLE_HELPER"

// startHelper runs bin as TestDumpableHelper in the given mode and returns its
// PID once it is ready. The child exits when the test ends.
func startHelper(t *testing.T, bin, mode string) string {
	t.Helper()
	cmd := exec.Command(bin, "-test.run=^TestDumpableHelper$")
	cmd.Env = append(os.Environ(), helperEnv+"="+mode)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); _ = cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper: %q %v", line, err)
	}
	return strconv.Itoa(cmd.Process.Pid)
}

func assertProcDenied(t *testing.T, pid string) {
	t.Helper()
	if _, err := os.Readlink("/proc/" + pid + "/root"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("/proc/%s/root: want permission denied, got %v", pid, err)
	}
	// Following an fd link is the ptrace-checked step (listing the directory
	// is a plain DAC check that UID 0 passes).
	if _, err := os.Readlink("/proc/" + pid + "/fd/0"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("/proc/%s/fd/0: want permission denied, got %v", pid, err)
	}
	if _, err := os.ReadFile("/proc/" + pid + "/environ"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("/proc/%s/environ: want permission denied, got %v", pid, err)
	}
	// status stays readable: the exporter's allowed reads still work.
	if _, err := os.ReadFile("/proc/" + pid + "/status"); err != nil {
		t.Errorf("/proc/%s/status must stay readable: %v", pid, err)
	}
}

// TestDumpableHelper is the child of the tests above. In "prctl" mode it
// calls nonDumpable; in "exec" mode it does nothing, so only execve decides.
func TestDumpableHelper(t *testing.T) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	if mode == "prctl" {
		if err := nonDumpable(); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("ready")
	_, _ = io.ReadAll(os.Stdin)
}

func hasCap(t *testing.T, c int) bool {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			return caps&(1<<c) != 0
		}
	}
	t.Fatal("no CapEff in /proc/self/status")
	return false
}
