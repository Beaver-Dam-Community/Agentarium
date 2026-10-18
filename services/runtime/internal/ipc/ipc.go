// Package ipc is the supervisor↔worker channel (TASK-15 dedicated IPC): one
// already-connected socketpair per worker, newline-delimited JSON, limited to
// bootstrap and typed action requests. Nothing a worker sends is authority:
// the supervisor routes by the channel it created, never by an ID inside a
// message.
package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/isolation"
)

// MaxMessage bounds one message line.
const MaxMessage = 64 << 10

// Message types.
const (
	// worker → supervisor
	TypeBootstrapAck = "bootstrap_ack" // controls applied (or failed), waiting without payload
	TypeStarted      = "started"       // task runner entered (agent_work_started)
	TypeSubmitAction = "submit_action" // one typed action request
	TypeDone         = "done"          // work finished, worker exits
	// supervisor → worker
	TypeGo           = "go"            // work released: task payload
	TypeActionResult = "action_result" // gateway outcome of the last request
	TypeStop         = "stop"          // exit without work
)

// Task is the work handed to the worker after release. The M3-1 minimal
// runtime has one deterministic task: one receiver.submit with a fixed
// payload (TASK-15 3.4 deterministic client).
type Task struct {
	ActionTimeoutMS int64   `json:"action_timeout_ms"`
	ConversationID  string  `json:"conversation_id"`
	TaskStatement   string  `json:"task_statement"`
	TargetID        string  `json:"target_id"`
	Summary         string  `json:"summary"`
	Email           *string `json:"email"`
}

// ActionRequest is a worker's typed request. The supervisor fills
// session_id and client_request_key itself.
type ActionRequest struct {
	OperationID     string          `json:"operation_id"`
	RequestedTarget json.RawMessage `json:"requested_target"`
	Arguments       json.RawMessage `json:"arguments"`
}

// ActionOutcome is what the worker learns about its request.
type ActionOutcome struct {
	ResultFinal    bool            `json:"result_final"`
	ActionID       string          `json:"action_id,omitempty"`
	Verdict        string          `json:"verdict,omitempty"`
	ExecutionState string          `json:"execution_state,omitempty"`
	ReasonCodes    []string        `json:"reason_codes"`
	HTTPStatus     int             `json:"http_status,omitempty"`
	ResultBody     json.RawMessage `json:"result_body,omitempty"`
	Truncated      bool            `json:"truncated"`
}

// Message is one line on the channel.
type Message struct {
	Type      string            `json:"type"`
	Controls  *isolation.Report `json:"controls,omitempty"`
	Error     string            `json:"error,omitempty"`
	WorkRunID string            `json:"work_run_id,omitempty"`
	Task      *Task             `json:"task,omitempty"`
	Action    *ActionRequest    `json:"action,omitempty"`
	Result    *ActionOutcome    `json:"result,omitempty"`
	Outcome   string            `json:"outcome,omitempty"`
}

// Conn frames messages on a byte stream.
type Conn struct {
	rw  io.ReadWriteCloser
	r   *bufio.Reader
	wmu sync.Mutex
}

func New(rw io.ReadWriteCloser) *Conn { return &Conn{rw: rw, r: bufio.NewReaderSize(rw, 4096)} }

// ErrTooLarge is a line over MaxMessage.
var ErrTooLarge = errors.New("ipc: message too large")

func (c *Conn) Send(m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > MaxMessage {
		return ErrTooLarge
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.rw.Write(append(b, '\n'))
	return err
}

// Recv reads one message. Unknown fields are refused.
func (c *Conn) Recv() (Message, error) {
	var line []byte
	for {
		chunk, isPrefix, err := c.r.ReadLine()
		if err != nil {
			return Message{}, err
		}
		line = append(line, chunk...)
		if len(line) > MaxMessage {
			return Message{}, ErrTooLarge
		}
		if !isPrefix {
			break
		}
	}
	var m Message
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return Message{}, fmt.Errorf("ipc: %w", err)
	}
	if m.Type == "" {
		return Message{}, errors.New("ipc: message without type")
	}
	return m, nil
}

func (c *Conn) Close() error { return c.rw.Close() }
