package normalize

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

// checkRaw validates the original grammar/keys/Unicode without applying the
// COMMON safe-integer bound to upstream uint64 numbers. It replaces numeric
// tokens only in a validation copy, never in the input used for decoding. Token
// offsets preserve strings and duplicate keys exactly. No float64 conversion.
func checkRaw(raw []byte) error {
	if len(raw) == 0 || len(raw) > wal.MaxRecordBytes {
		return errors.New("invalid Tetragon input size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var masked bytes.Buffer
	previous := int64(0)
	depth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("invalid Tetragon JSON")
		}
		if d, ok := token.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
			if depth > 64 {
				return errors.New("Tetragon JSON nesting exceeds limit")
			}
		}
		if n, ok := token.(json.Number); ok {
			end := decoder.InputOffset()
			start := end - int64(len(n.String()))
			if start < previous {
				return errors.New("invalid numeric token")
			}
			masked.Write(raw[previous:start])
			masked.WriteByte('0')
			previous = end
		}
	}
	masked.Write(raw[previous:])
	if canonical.CheckStrictJSON(masked.Bytes()) != nil {
		return errors.New("invalid Tetragon JSON shape")
	}
	return nil
}

type uint64Token uint64

func (v *uint64Token) UnmarshalJSON(raw []byte) error {
	var s string
	if len(raw) > 0 && raw[0] == '"' {
		if json.Unmarshal(raw, &s) != nil {
			return errors.New("invalid uint64")
		}
	} else {
		s = string(raw)
	}
	if s == "" {
		return errors.New("invalid uint64")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return errors.New("invalid uint64")
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return errors.New("invalid uint64")
	}
	*v = uint64Token(n)
	return nil
}

type rawEvent struct {
	Exec        *rawProcessEvent `json:"process_exec"`
	Exit        *rawExit         `json:"process_exit"`
	Kprobe      *rawKprobe       `json:"process_kprobe"`
	NodeName    string           `json:"node_name"`
	Time        string           `json:"time"`
	Aggregation json.RawMessage  `json:"aggregation_info"`
}
type rawProcessEvent struct {
	Process *rawProcess `json:"process"`
}
type rawExit struct {
	Process *rawProcess `json:"process"`
	Status  uint32      `json:"status"` // proto3 scalar default is zero, including omitted JSON.
	Signal  string      `json:"signal"`
}
type rawProcess struct {
	ExecID       string  `json:"exec_id"`
	ParentExecID string  `json:"parent_exec_id"`
	PID          *uint32 `json:"pid"`
	UID          *uint32 `json:"uid"`
	StartTime    string  `json:"start_time"`
	Docker       string  `json:"docker"`
	Binary       string  `json:"binary"`
	CWD          string  `json:"cwd"`
	InInitTree   *bool   `json:"in_init_tree"`
	NS           struct {
		Net *struct {
			Inum uint32 `json:"inum"`
		} `json:"net"`
		// PID namespace (enableProcessNs). Kept in memory only for the
		// worker-observation witness; it is not a KernelEvent field.
		PID *struct {
			Inum uint32 `json:"inum"`
		} `json:"pid"`
	} `json:"ns"`
	// Deliberately no argv, environment, Pod labels, raw Pod UID or container ID.
}
type rawKprobe struct {
	Process  *rawProcess `json:"process"`
	Function string      `json:"function_name"`
	Policy   string      `json:"policy_name"`
	Args     []rawArg    `json:"args"`
	Return   *rawArg     `json:"return"`
}
type rawArg struct {
	Sock   *rawSock `json:"sock_arg"`
	Int    *int32   `json:"int_arg"`
	String *string  `json:"string_arg"`
	File   *struct {
		Path string `json:"path"`
	} `json:"file_arg"`
	// file_arg.flags are path-resolution flags, not observed open access flags.
}
type rawSock struct {
	Family   string       `json:"family"`
	Protocol string       `json:"protocol"`
	Type     string       `json:"type"`
	SAddr    string       `json:"saddr"`
	DAddr    string       `json:"daddr"`
	SPort    uint32       `json:"sport"`
	DPort    uint32       `json:"dport"`
	Cookie   *uint64Token `json:"cookie"`
}

// KprobeArgument is a protobuf oneof. Reject mixed or unsupported shapes rather
// than interpreting one member and silently ignoring a conflicting argument.
func (a *rawArg) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 1 {
		return ErrInvalid
	}
	for key, value := range fields {
		if string(value) == "null" {
			return ErrInvalid
		}
		switch key {
		case "sock_arg", "int_arg", "string_arg", "file_arg":
		default:
			return ErrUnsupported
		}
	}
	type plain rawArg
	var p plain
	if json.Unmarshal(raw, &p) != nil {
		return ErrInvalid
	}
	*a = rawArg(p)
	return nil
}
