// Package probes compares the kernel-stimulus answer key with observed
// KernelEvents (TASK-09 7: behaviour observation, connection attempt and establishment, denied open). It is a
// deterministic checker: it never infers a match from Pod labels or process
// names, and an absent observation is "failed", not "unknown".
package probes

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Stimulus is one kernel-stimulus (or Q0 q0-stimulus) record.
type Stimulus struct {
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

type Tuple struct {
	SAddr string `json:"saddr"`
	SPort int    `json:"sport"`
	DAddr string `json:"daddr"`
	DPort int    `json:"dport"`
}

// Event holds the KernelEvent fields the checks use. Raw is the exact record
// when it came from the WAL; DB rows have no raw record.
type Event struct {
	SourceEventID  string          `json:"source_event_id"`
	SensorID       string          `json:"sensor_id"`
	SourceEpoch    string          `json:"source_epoch"`
	SourceSequence int64           `json:"source_sequence"`
	SourceTime     time.Time       `json:"source_time"`
	EventType      string          `json:"event_type"`
	PodUID         *string         `json:"pod_uid"`
	ContainerID    *string         `json:"container_id"`
	SocketTuple    *Tuple          `json:"socket_tuple"`
	SockPtr        *string         `json:"sock_ptr"`
	TCPNewState    *int            `json:"tcp_new_state"`
	SafeAttributes map[string]any  `json:"safe_attributes"`
	RecordDigest   string          `json:"record_digest"`
	Raw            json.RawMessage `json:"-"`
}

type Input struct {
	Stimuli []Stimulus
	Events  []Event
	// PodUID is the stimulus Pod's UID from the Kubernetes API.
	PodUID string
	// VerifyRaw recomputes source_event_id and record_digest from Raw.
	VerifyRaw bool
}

// Case follows the COMMON result-record vocabulary.
type Case struct {
	ID       string `json:"case_id"`
	Status   string `json:"status"` // passed, failed, not_run
	Expected int    `json:"expected"`
	Observed int    `json:"observed"`
	// EventIDs are the source_event_ids that satisfied the case (TASK-09 7
	// "event ID matching"), sorted.
	EventIDs []string `json:"event_ids"`
	Detail   string   `json:"detail,omitempty"`
}

type Report struct {
	Cases        []Case   `json:"cases"`
	Events       int      `json:"events_in_window"`
	IntegrityErr []string `json:"integrity_errors"`
}

func (r Report) Passed() bool {
	if len(r.IntegrityErr) != 0 {
		return false
	}
	for _, c := range r.Cases {
		if c.Status == "failed" {
			return false
		}
	}
	return true
}

func ReadStimuli(r io.Reader) ([]Stimulus, error) {
	var out []Stimulus
	s := bufio.NewScanner(r)
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		line := bytes.TrimSpace(s.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue // container log noise
		}
		var st Stimulus
		if err := json.Unmarshal(line, &st); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, s.Err()
}

// ReadEvents reads NDJSON KernelEvents (exporter inspect-wal or the DB query
// in run-live.sh). keepRaw retains exact bytes for integrity verification.
func ReadEvents(r io.Reader, keepRaw bool) ([]Event, error) {
	var out []Event
	s := bufio.NewScanner(r)
	s.Buffer(nil, 2<<20)
	for s.Scan() {
		line := bytes.TrimSpace(s.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, err
		}
		if keepRaw {
			e.Raw = append(json.RawMessage(nil), line...)
		}
		out = append(out, e)
	}
	return out, s.Err()
}

func parseTuple(local, remote string) (Tuple, error) {
	l, err := netip.ParseAddrPort(local)
	if err != nil {
		return Tuple{}, err
	}
	r, err := netip.ParseAddrPort(remote)
	if err != nil {
		return Tuple{}, err
	}
	return Tuple{l.Addr().String(), int(l.Port()), r.Addr().String(), int(r.Port())}, nil
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func number(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), x == float64(int64(x))
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	}
	return 0, false
}

// Evaluate runs the deterministic checks. Events outside the stimulus window
// (start-5s .. done+60s) are ignored.
func Evaluate(in Input) (Report, error) {
	var start, done time.Time
	by := map[string][]Stimulus{}
	for _, s := range in.Stimuli {
		t, err := time.Parse(time.RFC3339Nano, s.Time)
		if err != nil {
			return Report{}, fmt.Errorf("stimulus time: %w", err)
		}
		switch s.Kind {
		case "start":
			start = t
		case "done":
			done = t
		default:
			by[s.Kind] = append(by[s.Kind], s)
		}
	}
	if start.IsZero() || done.IsZero() {
		return Report{}, errors.New("stimulus log needs start and done records")
	}
	var rep Report
	var events []Event
	for _, e := range in.Events {
		if e.SourceTime.Before(start.Add(-5*time.Second)) || e.SourceTime.After(done.Add(60*time.Second)) {
			continue
		}
		events = append(events, e)
		if in.VerifyRaw {
			id, err := canonical.KernelEventID(e.SensorID, e.SourceEpoch, e.SourceSequence)
			digest, derr := canonical.DigestWithoutKeys(e.Raw, "record_digest", "received_at")
			if err != nil || derr != nil || id != e.SourceEventID || digest != e.RecordDigest {
				rep.IntegrityErr = append(rep.IntegrityErr, "identity/digest mismatch "+e.SourceEventID)
			}
		}
	}
	rep.Events = len(events)
	ofPod := func(e Event) bool { return str(e.PodUID) == in.PodUID && str(e.ContainerID) != "" }
	match := func(f func(Event) bool) []string {
		var ids []string
		for _, e := range events {
			if f(e) {
				ids = append(ids, e.SourceEventID)
			}
		}
		return ids
	}
	ok := func(kind string) int {
		n := 0
		for _, s := range by[kind] {
			if s.OK {
				n++
			}
		}
		return n
	}
	atLeast := func(id string, expected int, ids []string, detail string) Case {
		sort.Strings(ids)
		if ids == nil {
			ids = []string{}
		}
		c := Case{ID: id, Expected: expected, Observed: len(ids), EventIDs: ids, Detail: detail, Status: "passed"}
		observed := len(ids)
		if expected == 0 {
			c.Status = "not_run"
		} else if observed < expected {
			c.Status = "failed"
		}
		return c
	}

	// process_exec / process_exit of the stimulus binary in the stimulus Pod.
	binaries := map[string]bool{}
	for _, s := range by["process"] {
		binaries[s.Path] = true
		binaries[canonical.SHA256Hex([]byte(s.Path))] = true
	}
	execs := match(func(e Event) bool {
		b, _ := e.SafeAttributes["binary"].(string)
		return e.EventType == "process_exec" && ofPod(e) && binaries[b]
	})
	exits := match(func(e Event) bool { return e.EventType == "process_exit" && ofPod(e) })
	// +1: the stimulus process itself is also exec'd.
	rep.Cases = append(rep.Cases,
		atLeast("process_exec", ok("process")+boolInt(ok("process") > 0), execs, "binary plaintext or SHA-256 digest of the stimulus path"),
		atLeast("process_exit", ok("process"), exits, "children exit before stimulus end"))

	// TCP: attempt = tcp_connect with the attempted tuple; establishment =
	// tcp_state 1 and close = tcp_state 7 on the same sock_ptr and tuple.
	tcp := func(kind string, wantEstablished bool) []Case {
		var connects, established, closes, linked []string
		expected := 0
		for _, s := range by[kind] {
			// A stimulus without an attempted tuple (local port never bound)
			// is still expected and therefore fails.
			expected++
			want, err := parseTuple(s.Local, s.Remote)
			if s.Local == "" || err != nil {
				continue
			}
			var connect *Event
			for i := range events {
				e := &events[i]
				if e.EventType == "tcp_connect" && ofPod(*e) && e.SocketTuple != nil && *e.SocketTuple == want && e.SockPtr != nil {
					connect = e
				}
			}
			if connect == nil {
				continue
			}
			connects = append(connects, connect.SourceEventID)
			states := map[int]string{}
			for _, e := range events {
				if e.EventType == "tcp_state" && e.SockPtr != nil && *e.SockPtr == *connect.SockPtr && e.SocketTuple != nil && *e.SocketTuple == want && e.TCPNewState != nil {
					states[*e.TCPNewState] = e.SourceEventID
				}
			}
			if id, ok := states[1]; ok {
				established = append(established, id)
			}
			if id, ok := states[7]; ok {
				closes = append(closes, id)
			}
			if _, est := states[1]; est == wantEstablished && states[7] != "" {
				linked = append(linked, states[7])
			}
		}
		if kind == "tcp" {
			return []Case{
				atLeast("tcp_connect_attempt", expected, connects, "tcp_connect with the stimulus tuple (Go connects are non-blocking: connect then poll)"),
				atLeast("tcp_established_linked", expected, established, "tcp_state 1 on the connect sock_ptr and tuple"),
				atLeast("tcp_close_linked", expected, closes, "tcp_state 7 on the connect sock_ptr and tuple"),
			}
		}
		c := atLeast("tcp_failed_not_established", expected, linked, "connect + tcp_state 7 without tcp_state 1")
		return []Case{atLeast("tcp_failed_attempt", expected, connects, "tcp_connect with the stimulus tuple"), c}
	}
	rep.Cases = append(rep.Cases, tcp("tcp", true)...)
	rep.Cases = append(rep.Cases, tcp("tcp_failed", false)...)

	// Protected file: security_file_open sees only permitted opens; openat sees
	// both, with -13 for the DAC-denied attempts.
	fixtures := map[string]bool{}
	for _, k := range []string{"file_open_allowed", "file_open_denied"} {
		for _, s := range by[k] {
			fixtures[s.Path] = true
		}
	}
	pathOf := func(e Event) bool { p, _ := e.SafeAttributes["path"].(string); return fixtures[p] }
	fileOpens := match(func(e Event) bool {
		rc, okNum := number(e.SafeAttributes["return_code"])
		return e.EventType == "file_open" && ofPod(e) && pathOf(e) && okNum && rc == 0
	})
	openatOK := match(func(e Event) bool {
		_, hasErr := e.SafeAttributes["return_errno"]
		return e.EventType == "openat" && ofPod(e) && pathOf(e) && !hasErr
	})
	denied := 0
	for _, s := range by["file_open_denied"] {
		if !s.OK && strings.Contains(s.Errno, "permission denied") {
			denied++
		}
	}
	openatDenied := match(func(e Event) bool {
		n, okNum := number(e.SafeAttributes["return_errno"])
		return e.EventType == "openat" && ofPod(e) && pathOf(e) && okNum && n == -13
	})
	rep.Cases = append(rep.Cases,
		atLeast("file_open_allowed", ok("file_open_allowed"), fileOpens, "security_file_open return_code 0"),
		atLeast("openat_allowed", ok("file_open_allowed"), openatOK, "openat without return_errno"),
		atLeast("openat_denied_eacces", denied, openatDenied, "openat return_errno -13"))
	// Support table row: security_file_open must not see DAC-denied opens.
	// Permitted opens are the allowed reads plus the one fixture creation.
	permitted := ok("file_open_allowed") + 1
	extra := atLeast("file_open_not_on_denied", permitted, append([]string(nil), fileOpens...), "security_file_open count equals permitted opens (reads + fixture creation)")
	if denied == 0 {
		extra.Status = "not_run"
	} else if extra.Observed != permitted {
		extra.Status = "failed"
	}
	rep.Cases = append(rep.Cases, extra)
	return rep, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Merge unions WAL and stored events by source_event_id. A stored row whose
// record_digest differs from the fsynced WAL record is an integrity error.
func Merge(wal, stored []Event) ([]Event, []string) {
	byID := map[string]int{}
	var out []Event
	var conflicts []string
	for _, e := range wal {
		byID[e.SourceEventID] = len(out)
		out = append(out, e)
	}
	for _, e := range stored {
		if i, ok := byID[e.SourceEventID]; ok {
			if out[i].RecordDigest != e.RecordDigest {
				conflicts = append(conflicts, "stored digest differs from WAL "+e.SourceEventID)
			}
			continue
		}
		byID[e.SourceEventID] = len(out)
		out = append(out, e)
	}
	return out, conflicts
}
