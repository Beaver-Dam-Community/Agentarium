// Command q0-stimulus is the answer-key side of the M0-3 Q0 minimum run
// (TASK-01 7 runtime observation, TASK-09 3.2): it performs a fixed number of each
// kernel behaviour and prints one JSON line per stimulus, so the sensor
// events can be matched against an independent record. It runs as the
// probe-runner profile in agent-exec (no args; configuration via env).
//
//	Q0_COUNT       stimuli per kind (default 30)
//	Q0_TCP_TARGET  host:port for tcp_connect (required)
//	Q0_FIXTURE     protected path (default /work/protected-fixture, TASK-09 3.2)
//
// Kinds: process (fork+exec of this binary in child mode), tcp (connect to
// Q0_TCP_TARGET), file_open_allowed (open of the fixture with mode 0600),
// file_open_denied (open after chmod 000, EACCES for the non-root user).
// After the last stimulus it waits for SIGTERM so the log can be collected.
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

func main() {
	if os.Getenv("Q0_CHILD") == "1" {
		return
	}
	n := 30
	if v, err := strconv.Atoi(os.Getenv("Q0_COUNT")); err == nil && v > 0 {
		n = v
	}
	target := os.Getenv("Q0_TCP_TARGET")
	fixture := os.Getenv("Q0_FIXTURE")
	if fixture == "" {
		fixture = "/work/protected-fixture"
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "executable:", err)
		os.Exit(1)
	}
	emit(record{Kind: "start", OK: true, PID: os.Getpid()})

	for i := 0; i < n; i++ {
		cmd := exec.Command(self)
		cmd.Env = append(os.Environ(), "Q0_CHILD=1")
		err := cmd.Run()
		r := record{Kind: "process", Seq: i, Path: self, OK: err == nil, Errno: errnoName(err)}
		if cmd.Process != nil {
			r.PID = cmd.Process.Pid
		}
		emit(r)
	}

	for i := 0; i < n && target != ""; i++ {
		c, err := net.DialTimeout("tcp", target, 3*time.Second)
		r := record{Kind: "tcp", Seq: i, Remote: target, OK: err == nil, Errno: errnoName(err)}
		if c != nil {
			r.Local = c.LocalAddr().String()
			c.Close()
		}
		emit(r)
		time.Sleep(50 * time.Millisecond)
	}

	if err := os.WriteFile(fixture, []byte("synthetic q0 fixture\n"), 0o600); err != nil {
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
