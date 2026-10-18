package worker

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/ipc"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/isolation"
)

func ok() (isolation.Report, error) { return isolation.Report{Profile: isolation.Expected()}, nil }

// The worker sends nothing but its ack before go, and nothing at all when
// stopped in bootstrap.
func TestWaitsInBootstrapUntilGo(t *testing.T) {
	a, b := net.Pipe()
	sup := ipc.New(a)
	done := make(chan string, 1)
	go func() { out, _ := Run(ipc.New(b), ok, nil); done <- out }()
	m, err := sup.Recv()
	if err != nil || m.Type != ipc.TypeBootstrapAck || m.Controls == nil || m.Error != "" {
		t.Fatalf("ack %+v %v", m, err)
	}
	if err := sup.Send(ipc.Message{Type: ipc.TypeStop}); err != nil {
		t.Fatal(err)
	}
	if out := <-done; out != "stopped" {
		t.Fatalf("outcome %q", out)
	}
}

func TestIsolationFailureStops(t *testing.T) {
	a, b := net.Pipe()
	sup := ipc.New(a)
	errc := make(chan error, 1)
	go func() {
		_, err := Run(ipc.New(b), func() (isolation.Report, error) { return isolation.Report{}, errors.New("boom") }, nil)
		errc <- err
	}()
	m, _ := sup.Recv()
	if m.Type != ipc.TypeBootstrapAck || m.Error != "boom" {
		t.Fatalf("ack %+v", m)
	}
	if err := <-errc; err == nil {
		t.Fatal("worker continued after isolation failure")
	}
}

func TestOneReceiverRequest(t *testing.T) {
	a, b := net.Pipe()
	sup := ipc.New(a)
	done := make(chan string, 1)
	go func() { out, _ := Run(ipc.New(b), ok, nil); done <- out }()
	_, _ = sup.Recv()
	email := "user@example.com"
	_ = sup.Send(ipc.Message{Type: ipc.TypeGo, WorkRunID: "r", Task: &ipc.Task{TargetID: "receiver-primary", Summary: "s", Email: &email}})
	if m, _ := sup.Recv(); m.Type != ipc.TypeStarted {
		t.Fatalf("got %+v", m)
	}
	m, _ := sup.Recv()
	if m.Type != ipc.TypeSubmitAction || m.Action.OperationID != OperationReceiverSubmit ||
		string(m.Action.RequestedTarget) != `{"target_id":"receiver-primary"}` ||
		!strings.Contains(string(m.Action.Arguments), `"email":"user@example.com"`) {
		t.Fatalf("request %+v", m.Action)
	}
	_ = sup.Send(ipc.Message{Type: ipc.TypeActionResult, Result: &ipc.ActionOutcome{Verdict: "allow", ExecutionState: "accepted"}})
	if m, _ := sup.Recv(); m.Type != ipc.TypeDone || m.Outcome != "accepted" {
		t.Fatalf("done %+v", m)
	}
	if out := <-done; out != "accepted" {
		t.Fatalf("outcome %q", out)
	}
}
