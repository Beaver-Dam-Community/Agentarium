package testfixture

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// BuildBinary builds a package of this repository into dir.
func BuildBinary(t *testing.T, dir, name, pkg string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = RepoRoot()
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v %s", pkg, err, b)
	}
	return out
}

func FreeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// Process is a started binary with captured output.
type Process struct {
	Cmd  *exec.Cmd
	mu   sync.Mutex
	logs bytes.Buffer
	done chan struct{}
}

type lockedWriter struct{ p *Process }

func (w lockedWriter) Write(b []byte) (int, error) {
	w.p.mu.Lock()
	defer w.p.mu.Unlock()
	return w.p.logs.Write(b)
}

// Start runs bin with args and extra environment. The process is killed when
// the test ends if it is still running.
func Start(t *testing.T, bin string, env []string, args ...string) *Process {
	t.Helper()
	p := &Process{Cmd: exec.Command(bin, args...), done: make(chan struct{})}
	p.Cmd.Env = append(os.Environ(), env...)
	p.Cmd.Stdout, p.Cmd.Stderr = lockedWriter{p}, lockedWriter{p}
	if err := p.Cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.Cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.Kill() })
	return p
}

func (p *Process) Logs() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logs.String()
}

// Exited reports whether the process has ended.
func (p *Process) Exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// Kill sends SIGKILL (abrupt Pod deletion: no shutdown hook runs) and waits.
func (p *Process) Kill() {
	if p.Cmd.Process != nil && !p.Exited() {
		_ = p.Cmd.Process.Signal(syscall.SIGKILL)
	}
	<-p.done
}

// WaitListening waits until addr accepts TCP connections.
func (p *Process) WaitListening(t *testing.T, addr string) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if p.Exited() {
			break
		}
		if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			conn.Close()
			return
		}
	}
	t.Fatalf("process did not start listening: %s", p.Logs())
}

// Eventually polls cond until it is true or the timeout passes.
func Eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}
