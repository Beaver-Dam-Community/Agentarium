//go:build integration

package m31

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// env is the run's fixed inputs from tests/m3-1/run-local.sh.
type env struct {
	repo, work, bin, rtBin string
	pgContainer            string
	pgPort, gcsHost        string
	runtimeImage           string
	runtimePlatform        string
	runTag                 string
}

func loadEnv(t *testing.T) env {
	t.Helper()
	if os.Getenv("M31_E2E_WORK") == "" {
		t.Skip("M31_E2E_WORK not set (run tests/m3-1/run-local.sh)")
	}
	get := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			t.Fatalf("%s is required", k)
		}
		return v
	}
	e := env{repo: get("M31_E2E_REPO"), work: get("M31_E2E_WORK"), bin: get("M31_E2E_BIN"), rtBin: get("M31_E2E_RUNTIME_BIN"),
		pgContainer: get("M31_E2E_PG_CONTAINER"), pgPort: get("M31_E2E_PG_PORT"), gcsHost: get("M31_E2E_GCS_HOST"),
		runtimeImage: get("M31_E2E_RUNTIME_IMAGE"), runtimePlatform: get("M31_E2E_RUNTIME_PLATFORM"), runTag: get("M31_E2E_RUN_TAG")}
	for _, d := range []string{"logs", "epochs", "cfg"} {
		if err := os.MkdirAll(filepath.Join(e.work, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// 0755: the runtime containers (uid 10001) read their token from here.
	if err := os.MkdirAll(filepath.Join(e.work, "tokens"), 0o755); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e env) path(parts ...string) string {
	return filepath.Join(append([]string{e.work}, parts...)...)
}

// freePort returns a currently unused loopback port.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, p, _ := net.SplitHostPort(l.Addr().String())
	return p
}

// proc is one service process started by the driver.
type proc struct {
	name string
	cmd  *exec.Cmd
	log  string
	done chan struct{}
	err  error
}

type procs struct {
	mu   sync.Mutex
	list []*proc
}

// start runs bin with args and extra environment, logging to logs/<name>.log.
func (ps *procs) start(t *testing.T, e env, name, bin string, args []string, extraEnv ...string) *proc {
	t.Helper()
	logPath := e.path("logs", name+".log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append(baseEnv(e), extraEnv...)
	cmd.Stdout, cmd.Stderr = f, f
	cmd.Dir = e.work
	if err := cmd.Start(); err != nil {
		f.Close()
		t.Fatalf("start %s: %v", name, err)
	}
	p := &proc{name: name, cmd: cmd, log: logPath, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		f.Close()
		close(p.done)
	}()
	ps.mu.Lock()
	ps.list = append(ps.list, p)
	ps.mu.Unlock()
	return p
}

// baseEnv is a minimal environment: no Google credentials or proxies leak in.
func baseEnv(e env) []string {
	return []string{"PATH=" + os.Getenv("PATH"), "HOME=" + e.work, "TMPDIR=" + e.path("cfg"),
		"STORAGE_EMULATOR_HOST=" + e.gcsHost, "GOOGLE_CLOUD_PROJECT=m31-local", "NO_PROXY=*"}
}

func (p *proc) alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *proc) stop() {
	if !p.alive() {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(15 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

func (ps *procs) stopAll() {
	ps.mu.Lock()
	list := append([]*proc(nil), ps.list...)
	ps.mu.Unlock()
	for i := len(list) - 1; i >= 0; i-- {
		list[i].stop()
	}
}

// tail returns the last n lines of a process log, for failure reports.
func (p *proc) tail(n int) string {
	f, err := os.Open(p.log)
	if err != nil {
		return ""
	}
	defer f.Close()
	var lines []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for s.Scan() {
		lines = append(lines, s.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return strings.Join(lines, "\n")
}

// waitFor polls cond until it returns nil or the timeout passes.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if last = cond(); last == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %v", what, last)
}

// step prints a stage header to the run log.
func step(format string, a ...any) {
	fmt.Printf("\n== %s\n", fmt.Sprintf(format, a...))
}

func info(format string, a ...any) { fmt.Printf("   %s\n", fmt.Sprintf(format, a...)) }

func bg() context.Context { return context.Background() }
