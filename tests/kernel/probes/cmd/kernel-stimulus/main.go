// Command kernel-stimulus is the independent answer key of the TASK-09 live
// observation check ("answer event observation", TASK-09 7 behaviour observation, connection attempt and establishment).
// It performs a fixed number of each kernel behaviour inside an agent-exec
// probe-runner Pod and prints one JSON line per stimulus. The record format is
// a superset of tests/platform/q0/cmd/q0-stimulus, so Q0 evidence can be used
// as offline input to kernel-assert.
//
//	STIMULUS_COUNT        stimuli per kind (default 10)
//	STIMULUS_TCP_OPEN     host:port expected to accept (ESTABLISHED then CLOSE)
//	STIMULUS_TCP_FAILED   host:port expected to refuse or drop (CLOSE only); optional
//	STIMULUS_FIXTURE      protected path (default /work/protected-fixture)
//
// Kinds: process (exec of this binary in child mode), tcp, tcp_failed,
// file_open_allowed (open of the fixture), file_open_denied (open after
// chmod 000 as a non-root user: EACCES). Each TCP attempt binds an explicit
// local port first, so the attempted tuple is known even when connect fails.
// After "done" it waits for SIGTERM so the log can be collected.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type record struct {
	Kind   string `json:"kind"`
	Seq    int    `json:"seq"`
	Time   string `json:"time"`
	PID    int    `json:"pid,omitempty"`
	Path   string `json:"path,omitempty"`
	Local  string `json:"local,omitempty"`
	Remote string `json:"remote,omitempty"`
	Errno  string `json:"errno,omitempty"`
	OK     bool   `json:"ok"`
}

func emit(r record) {
	r.Time = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

func errnoName(err error) string {
	var en syscall.Errno
	if errors.As(err, &en) {
		return en.Error()
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

// dial connects from an explicitly bound local port so the record carries the
// attempted tuple even when the connection is refused or times out.
func dial(local net.IP, target string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		port := 40000 + int(time.Now().UnixNano()%20000)
		laddr := &net.TCPAddr{IP: local, Port: port}
		d := net.Dialer{LocalAddr: laddr, Timeout: 3 * time.Second}
		c, err := d.Dial("tcp4", target)
		if errors.Is(err, syscall.EADDRINUSE) {
			lastErr = err
			continue
		}
		if c != nil {
			c.Close()
		}
		return laddr.String(), err
	}
	return "", lastErr
}

func podIP() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			return n.IP.To4(), nil
		}
	}
	return nil, errors.New("no IPv4 Pod address")
}

func main() {
	if os.Getenv("STIMULUS_CHILD") == "1" {
		return
	}
	n := 10
	if v, err := strconv.Atoi(os.Getenv("STIMULUS_COUNT")); err == nil && v > 0 && v <= 1000 {
		n = v
	}
	fixture := os.Getenv("STIMULUS_FIXTURE")
	if fixture == "" {
		fixture = "/work/protected-fixture"
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "executable:", err)
		os.Exit(1)
	}
	local, err := podIP()
	if err != nil {
		fmt.Fprintln(os.Stderr, "address:", err)
		os.Exit(1)
	}
	emit(record{Kind: "start", OK: true, PID: os.Getpid(), Path: self})

	for i := 0; i < n; i++ {
		cmd := exec.Command(self)
		cmd.Env = append(os.Environ(), "STIMULUS_CHILD=1")
		err := cmd.Run()
		r := record{Kind: "process", Seq: i, Path: self, OK: err == nil, Errno: errnoName(err)}
		if cmd.Process != nil {
			r.PID = cmd.Process.Pid
		}
		emit(r)
	}
	for _, t := range []struct{ kind, target string }{{"tcp", os.Getenv("STIMULUS_TCP_OPEN")}, {"tcp_failed", os.Getenv("STIMULUS_TCP_FAILED")}} {
		for i := 0; i < n && t.target != ""; i++ {
			laddr, err := dial(local, t.target)
			emit(record{Kind: t.kind, Seq: i, Local: laddr, Remote: t.target, OK: err == nil, Errno: errnoName(err)})
			time.Sleep(50 * time.Millisecond)
		}
	}
	if err := os.WriteFile(fixture, []byte("synthetic kernel probe fixture\n"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "fixture:", err)
		os.Exit(1)
	}
	for i := 0; i < n; i++ {
		f, err := os.Open(fixture)
		emit(record{Kind: "file_open_allowed", Seq: i, Path: fixture, OK: err == nil, Errno: errnoName(err)})
		if f != nil {
			f.Close()
		}
	}
	if err := os.Chmod(fixture, 0); err != nil {
		fmt.Fprintln(os.Stderr, "chmod:", err)
		os.Exit(1)
	}
	for i := 0; i < n; i++ {
		f, err := os.Open(fixture)
		emit(record{Kind: "file_open_denied", Seq: i, Path: fixture, OK: err == nil, Errno: errnoName(err)})
		if f != nil {
			f.Close()
		}
	}
	emit(record{Kind: "done", OK: true})
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
	<-ch
}
