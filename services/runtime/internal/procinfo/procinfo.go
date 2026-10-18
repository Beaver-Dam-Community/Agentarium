// Package procinfo reads the process hints the supervisor reports for itself
// and its worker (COMMON SessionProcessBinding hints, TASK-15 session-dedicated
// worker): the container-local PID, the PID namespace inode and the start
// ticks, field 22 of /proc/<pid>/stat. The hints are location information
// for the node witness, never authority or observation evidence.
package procinfo

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// Hint mirrors control-health ProcessHint (#228 health.ProcessHint).
type Hint struct {
	LocalPID   int64 `json:"local_pid"`
	PIDNSInode int64 `json:"pid_ns_inode"`
	StartTicks int64 `json:"start_ticks"`
}

// Valid reports whether every field is positive (control-health refuses
// anything else).
func (h Hint) Valid() bool { return h.LocalPID > 0 && h.PIDNSInode > 0 && h.StartTicks > 0 }

// ErrUnsupported is returned where /proc is not available (non-Linux).
var ErrUnsupported = errors.New("procinfo: /proc process hints need Linux")

// StartTicks parses field 22 (starttime) of a /proc/<pid>/stat line
// (proc(5)). Field 2, comm, is in parentheses and may contain spaces and
// parentheses, so the fields are counted after the last ')'.
func StartTicks(stat []byte) (int64, error) {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, errors.New("procinfo: stat has no comm field")
	}
	fields := bytes.Fields(stat[i+1:])
	// fields[0] is field 3 (state), so field 22 is fields[19].
	const idx = 22 - 3
	if len(fields) <= idx {
		return 0, fmt.Errorf("procinfo: stat has %d fields after comm", len(fields))
	}
	v, err := strconv.ParseInt(string(fields[idx]), 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("procinfo: invalid starttime %q", fields[idx])
	}
	return v, nil
}
