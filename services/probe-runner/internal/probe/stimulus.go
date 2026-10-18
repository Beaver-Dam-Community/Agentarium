// Package probe runs the TASK-10 3.2 answer probes ("answer probe") on one node
// and reports their results with the COMMON probe-results wire.
//
// Every 60 seconds the runner gives each kind its stimulus, which the node
// sensors record as kernel events of this Pod's container:
//
//	process  exec of the fixed binary /probe/bin/marker   process_exec, process_exit
//	tcp      connect to probe-sink:8443, then close       tcp_connect, tcp_state ESTABLISHED and CLOSE (same tuple)
//	file     read the fixture, then open it unreadable     security_file_open (0), openat (>= 0), openat (-13 EACCES)
//
// 25 seconds after each stimulus it reports the kind with stimulus_at. The
// runner cannot see kernel events or their source_event_id: control-health
// finds the evidence of the stimulus window itself and answers 409 while it
// is missing (TASK-10 3.2 "answer probe evidence recheck").
package probe

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Kinds are the node answer probe kinds (health.NodeProbeKinds).
var Kinds = []string{"process", "tcp", "file"}

// Defaults of the stimuli. The fixture path is the one path the
// agentarium-protected-file TracingPolicy watches (sensors/tetragon/policies
// file-access.yaml); the marker path is the TASK-10 3.2 table's binary.
const (
	DefaultMarker  = "/probe/bin/marker"
	DefaultFixture = "/work/protected-fixture"
	// StimulusTimeout bounds one stimulus; it ends well inside the 10s
	// evidence window after stimulus_at.
	StimulusTimeout = 3 * time.Second
)

// Stimulus performs one kind's behaviour. A nil error means the behaviour
// happened as intended, so the expected kernel events should exist.
type Stimulus func(ctx context.Context) error

// Marker execs the fixed marker binary with an empty environment and expects
// exit status 0 (process_exec and process_exit of this container).
func Marker(path string) Stimulus {
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, StimulusTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, path)
		cmd.Env = []string{}
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("process stimulus: %w", err)
		}
		return nil
	}
}

// Connect opens one IPv4 TCP connection to the probe sink and closes it
// (tcp_connect, tcp_state ESTABLISHED, tcp_state CLOSE on one tuple).
func Connect(addr string) Stimulus {
	return func(ctx context.Context) error {
		d := net.Dialer{Timeout: StimulusTimeout}
		c, err := d.DialContext(ctx, "tcp4", addr)
		if err != nil {
			return fmt.Errorf("tcp stimulus: %w", err)
		}
		if err := c.Close(); err != nil {
			return fmt.Errorf("tcp stimulus: close: %w", err)
		}
		return nil
	}
}

// Fixture reads the fixture while it is owner-readable, then makes it
// unreadable and opens it again, which a non-root process without
// CAP_DAC_OVERRIDE gets EACCES for. The allowed read gives
// security_file_open (return 0) and openat (return >= 0); the denied open
// gives openat (return -13), which security_file_open does not see.
func Fixture(path string) Stimulus {
	return func(context.Context) error {
		if err := os.Chmod(path, 0o600); errors.Is(err, fs.ErrNotExist) {
			if err := os.WriteFile(path, []byte("agentarium answer probe fixture\n"), 0o600); err != nil {
				return fmt.Errorf("file stimulus: create fixture: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("file stimulus: %w", err)
		}
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("file stimulus: allowed open: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("file stimulus: close: %w", err)
		}
		if err := os.Chmod(path, 0); err != nil {
			return fmt.Errorf("file stimulus: %w", err)
		}
		f, err = os.Open(path)
		if err == nil {
			_ = f.Close()
			return errors.New("file stimulus: unreadable fixture opened (runner has DAC override)")
		}
		if !errors.Is(err, syscall.EACCES) {
			return fmt.Errorf("file stimulus: denied open: %w, want EACCES", err)
		}
		return nil
	}
}
