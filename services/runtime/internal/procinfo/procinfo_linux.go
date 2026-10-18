//go:build linux

package procinfo

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// Of reads the hints of pid from procRoot (normally "/proc"): pid itself as
// the local PID (the supervisor and its workers share the container's PID
// namespace), the inode of the caller's own PID namespace and field 22 of
// /proc/<pid>/stat.
//
// The namespace is read from /proc/self/ns/pid, not /proc/<pid>/ns/pid: a
// worker that has set PR_SET_DUMPABLE=0 no longer lets a same-UID process
// without CAP_SYS_PTRACE open its ns links, and the worker cannot leave the
// supervisor's PID namespace (no CLONE_NEWPID/unshare/setns, isolation
// filter). /proc/<pid>/stat stays world-readable and starttime is not masked.
func Of(procRoot string, pid int) (Hint, error) {
	if pid <= 0 {
		return Hint{}, fmt.Errorf("procinfo: invalid pid %d", pid)
	}
	dir := procRoot + "/" + strconv.Itoa(pid)
	var st syscall.Stat_t
	if err := syscall.Stat(procRoot+"/self/ns/pid", &st); err != nil {
		return Hint{}, fmt.Errorf("procinfo: own pid namespace: %w", err)
	}
	raw, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return Hint{}, fmt.Errorf("procinfo: stat of %d: %w", pid, err)
	}
	ticks, err := StartTicks(raw)
	if err != nil {
		return Hint{}, err
	}
	h := Hint{LocalPID: int64(pid), PIDNSInode: int64(st.Ino), StartTicks: ticks}
	if !h.Valid() {
		return Hint{}, fmt.Errorf("procinfo: incomplete hint for %d", pid)
	}
	return h, nil
}
