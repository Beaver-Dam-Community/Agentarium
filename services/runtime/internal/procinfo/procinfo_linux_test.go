//go:build linux

package procinfo

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestOfSelfAndChild(t *testing.T) {
	self, err := Of("/proc", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/pid", &st); err != nil {
		t.Fatal(err)
	}
	if self.LocalPID != int64(os.Getpid()) || self.PIDNSInode != int64(st.Ino) || self.StartTicks <= 0 {
		t.Fatalf("self hint = %+v", self)
	}
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skip("no sleep binary:", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	child, err := Of("/proc", cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if child.PIDNSInode != self.PIDNSInode || child.LocalPID != int64(cmd.Process.Pid) || child.StartTicks < self.StartTicks || child == self {
		t.Fatalf("child hint = %+v, self %+v", child, self)
	}
}
