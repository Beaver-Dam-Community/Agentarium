//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// prctl and getDumpable are replaced only by tests.
var (
	prctl       = unix.Prctl
	getDumpable = func() (int, error) { return unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0) }
)

// nonDumpable applies PR_SET_DUMPABLE(0) and confirms it (TASK-01 3.2.1
// exporter host procfs deployment prerequisite, TASK-09 3.6). A non-dumpable process
// keeps a same-UID process such as the exporter from following
// /proc/<pid>/root or /proc/<pid>/fd to the host containerd socket. The
// process never sets dumpable back to 1 and never execs.
func nonDumpable() error {
	if err := prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_DUMPABLE(0): %w", err)
	}
	d, err := getDumpable()
	if err != nil {
		return fmt.Errorf("PR_GET_DUMPABLE: %w", err)
	}
	if d != 0 {
		return fmt.Errorf("dumpable is %d after PR_SET_DUMPABLE(0)", d)
	}
	return nil
}
