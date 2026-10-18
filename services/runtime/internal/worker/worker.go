// Package worker is the session-dedicated worker bootstrap (COMMON
// session-dedicated worker contract 2). After its final exec it applies the isolation
// controls, acknowledges them on its IPC channel and waits without any user
// payload. Only after the supervisor's go message does it run its task: in
// this minimal runtime one deterministic receiver.submit request (TASK-15
// 3.4 deterministic client). It holds no session token, certificate or key and
// makes no network call; every request goes to the supervisor over IPC.
package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/ipc"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/isolation"
)

// OperationReceiverSubmit is the only operation this worker requests.
const OperationReceiverSubmit = "receiver.submit"

// Run is the worker main loop. apply installs the isolation controls
// (isolation.Apply in the real binary). It returns the outcome string it
// reported, or an error.
func Run(conn *ipc.Conn, apply func() (isolation.Report, error), out io.Writer) (string, error) {
	rep, err := apply()
	ack := ipc.Message{Type: ipc.TypeBootstrapAck, Controls: &rep}
	if err != nil {
		ack.Error = err.Error()
	}
	if serr := conn.Send(ack); serr != nil {
		return "", serr
	}
	if err != nil {
		return "", fmt.Errorf("worker: isolation controls failed: %w", err)
	}
	m, err := conn.Recv()
	if err != nil {
		return "", err
	}
	switch m.Type {
	case ipc.TypeStop:
		return "stopped", nil
	case ipc.TypeGo:
	default:
		return "", fmt.Errorf("worker: unexpected %q while waiting in bootstrap", m.Type)
	}
	if m.Task == nil {
		return "", errors.New("worker: go without task")
	}
	if err := conn.Send(ipc.Message{Type: ipc.TypeStarted, WorkRunID: m.WorkRunID}); err != nil {
		return "", err
	}
	req, err := receiverRequest(*m.Task)
	if err != nil {
		return "", err
	}
	if err := conn.Send(ipc.Message{Type: ipc.TypeSubmitAction, Action: &req}); err != nil {
		return "", err
	}
	res, err := conn.Recv()
	if err != nil {
		return "", err
	}
	if res.Type == ipc.TypeStop {
		return "stopped", nil
	}
	if res.Type != ipc.TypeActionResult || res.Result == nil {
		return "", fmt.Errorf("worker: unexpected %q while waiting for the action result", res.Type)
	}
	outcome := Outcome(*res.Result)
	if out != nil {
		// Log status only; sanitized result bodies can still contain user data.
		summary := *res.Result
		summary.ResultBody = nil
		b, _ := json.Marshal(summary)
		fmt.Fprintf(out, "worker action result %s\n", b)
	}
	if err := conn.Send(ipc.Message{Type: ipc.TypeDone, Outcome: outcome}); err != nil {
		return outcome, err
	}
	return outcome, nil
}

// Outcome summarises a result: the execution_state when there is one,
// else the verdict, else the first reason code.
func Outcome(r ipc.ActionOutcome) string {
	switch {
	case r.ExecutionState != "":
		return r.ExecutionState
	case r.Verdict != "":
		return r.Verdict
	case len(r.ReasonCodes) > 0:
		return r.ReasonCodes[0]
	}
	return "unknown"
}

// receiverRequest is the fixed receiver.submit ClientAction content
// (canonical.ReceiverTarget / ReceiverArgs; email is null unless the task
// sets it).
func receiverRequest(t ipc.Task) (ipc.ActionRequest, error) {
	target, err := json.Marshal(canonical.ReceiverTarget{TargetID: t.TargetID})
	if err != nil {
		return ipc.ActionRequest{}, err
	}
	args, err := json.Marshal(canonical.ReceiverArgs{Payload: canonical.ReceiverPayload{Summary: t.Summary, Email: t.Email}})
	if err != nil {
		return ipc.ActionRequest{}, err
	}
	return ipc.ActionRequest{OperationID: OperationReceiverSubmit, RequestedTarget: target, Arguments: args}, nil
}
