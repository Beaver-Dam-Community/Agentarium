// Package spawn starts a session worker: one fork+exec of the fixed worker
// executable by the supervisor itself (no shell, wrapper or re-exec), so the
// supervisor is the worker's direct parent and the node sensor sees exactly
// one exec of the approved worker binary (COMMON session-dedicated worker contract,
// TASK-09 #232 observation requirements).
package spawn

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"

	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/ipc"
)

// Worker is a started worker process.
type Worker interface {
	Conn() *ipc.Conn
	Pid() int
	// Wait reaps the process; it is safe to call more than once.
	Wait() error
	Kill() error
}

// Exec starts Path with no arguments, an environment of only HOME and
// TMPDIR (the worker's scratch directory), the scratch directory as cwd, and
// one IPC socket as fd 3. stdout and stderr are read line by line into Log
// with the worker_instance_id attached.
type Exec struct {
	Path        string   // absolute path of the approved worker executable
	Args        []string // fixed bootstrap args supplied by the trusted entry point, never task input
	ScratchRoot string   // /work
	Log         *slog.Logger
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Spawn execs one worker for sessionID with workerInstanceID. The scratch
// directory /work/<session_id>/<worker_instance_id> is created 0700
// (TASK-15 file hygiene; not a security boundary between same-UID workers).
func (e Exec) Spawn(sessionID, workerInstanceID string) (Worker, error) {
	if !filepath.IsAbs(e.Path) || e.ScratchRoot == "" {
		return nil, errors.New("spawn: worker path must be absolute and scratch root set")
	}
	if !uuidRE.MatchString(sessionID) || !uuidRE.MatchString(workerInstanceID) {
		return nil, errors.New("spawn: session and worker IDs must be UUIDs")
	}
	scratch := filepath.Join(e.ScratchRoot, sessionID, workerInstanceID)
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return nil, fmt.Errorf("spawn: scratch: %w", err)
	}
	if err := os.Chmod(filepath.Join(e.ScratchRoot, sessionID), 0o700); err != nil {
		return nil, err
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("spawn: socketpair: %w", err)
	}
	// Both ends close on exec; ExtraFiles dup2s the child end to fd 3
	// without the flag, so no other descriptor reaches the worker.
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	parent := os.NewFile(uintptr(fds[0]), "ipc-supervisor")
	child := os.NewFile(uintptr(fds[1]), "ipc-worker")
	cmd := &exec.Cmd{
		Path:        e.Path,
		Args:        append([]string{e.Path}, e.Args...),
		Env:         []string{"HOME=" + scratch, "TMPDIR=" + scratch},
		Dir:         scratch,
		ExtraFiles:  []*os.File{child},
		SysProcAttr: sysProcAttr(),
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		parent.Close()
		child.Close()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		parent.Close()
		child.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		parent.Close()
		child.Close()
		return nil, fmt.Errorf("spawn: exec %s: %w", e.Path, err)
	}
	child.Close()
	log := e.Log
	if log == nil {
		log = slog.Default()
	}
	log = log.With("worker_instance_id", workerInstanceID, "worker_pid", cmd.Process.Pid)
	w := &execWorker{cmd: cmd, conn: ipc.New(parent), done: make(chan struct{})}
	w.pipes.Add(2)
	go w.drain(stdout, log, "stdout")
	go w.drain(stderr, log, "stderr")
	go func() {
		w.pipes.Wait() // StdoutPipe: read everything before Wait
		w.err = cmd.Wait()
		close(w.done)
	}()
	return w, nil
}

type execWorker struct {
	cmd   *exec.Cmd
	conn  *ipc.Conn
	pipes sync.WaitGroup
	done  chan struct{}
	err   error
}

func (w *execWorker) Conn() *ipc.Conn { return w.conn }
func (w *execWorker) Pid() int        { return w.cmd.Process.Pid }
func (w *execWorker) Wait() error {
	<-w.done
	return w.err
}
func (w *execWorker) Kill() error {
	select {
	case <-w.done:
		return nil
	default:
	}
	return w.cmd.Process.Kill()
}

// drain logs worker output lines (bounded) with the worker binding context.
// The worker never holds a token, so its output carries none; lines are
// still capped.
func (w *execWorker) drain(r io.Reader, log *slog.Logger, stream string) {
	defer w.pipes.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 16<<10)
	for sc.Scan() {
		log.Info("worker output", "stream", stream, "line", sc.Text())
	}
	_, _ = io.Copy(io.Discard, r)
}
