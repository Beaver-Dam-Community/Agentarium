// Package checks validates IAM policy JSON (as printed by
// `gcloud ... get-iam-policy --format=json`) against the TASK-01/TASK-06
// rules: no grant to agent-exec principals, principalSets or whole GKE
// workload pools, and no reference to another environment's workload pool.
package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Policy is the subset of the IAM Policy resource the checks read.
type Policy struct {
	Version      json.Number     `json:"version,omitempty"`
	Etag         string          `json:"etag,omitempty"`
	Bindings     []Binding       `json:"bindings,omitempty"`
	AuditConfigs json.RawMessage `json:"auditConfigs,omitempty"`
}

// Binding is one role binding of an IAM policy.
type Binding struct {
	Role      string     `json:"role"`
	Members   []string   `json:"members"`
	Condition *Condition `json:"condition,omitempty"`
}

// Condition is an IAM condition expression.
type Condition struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Expression  string `json:"expression,omitempty"`
}

const maxDepth = 32

// ParsePolicy decodes an IAM policy strictly: duplicate object keys (also
// keys that differ only by case), keys whose spelling differs from the IAM
// field names, excessive nesting, unknown fields and trailing data are
// rejected so that a malformed file cannot hide a member from the checks.
// encoding/json matches field names case-insensitively, so the exact-name
// check has to happen before decoding.
func ParsePolicy(data []byte) (*Policy, error) {
	if err := precheck(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode policy: trailing data after policy object")
	}
	return &p, nil
}

// schema lists the exact object keys allowed at a position. A nil schema
// accepts any keys (auditConfigs is kept raw and never read by the checks).
type schema struct {
	fields map[string]*schema // object keys and the schema of their values
	elem   *schema            // array element schema
}

var (
	conditionSchema = &schema{fields: map[string]*schema{"title": nil, "description": nil, "expression": nil}}
	bindingSchema   = &schema{fields: map[string]*schema{"role": nil, "members": {}, "condition": conditionSchema}}
	policySchema    = &schema{fields: map[string]*schema{
		"version":      nil,
		"etag":         nil,
		"bindings":     {elem: bindingSchema},
		"auditConfigs": nil,
	}}
)

// precheck walks the token stream once to reject duplicate or case-colliding
// keys, keys not spelled exactly as the IAM fields, and deep nesting.
func precheck(data []byte) error { return precheckWith(data, policySchema) }

// precheckWith is precheck against an arbitrary top-level schema.
func precheckWith(data []byte, root *schema) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		object  bool
		schema  *schema // nil: keys unchecked
		keys    map[string]string
		wantKey bool
		child   *schema // schema of the value after the current key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("parse policy: %w", err)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				var s *schema
				switch {
				case top == nil:
					s = root
				case top.object:
					s = top.child
					top.wantKey = true
				case top.schema != nil:
					s = top.schema.elem
				}
				if len(stack) >= maxDepth {
					return errors.New("parse policy: nesting too deep")
				}
				stack = append(stack, &frame{object: d == '{', schema: s, keys: map[string]string{}, wantKey: true})
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil || !top.object {
			continue
		}
		if !top.wantKey {
			top.wantKey = true
			continue
		}
		key, _ := tok.(string)
		folded := strings.ToLower(key)
		if prev, dup := top.keys[folded]; dup {
			if prev == key {
				return fmt.Errorf("parse policy: duplicate key %q", key)
			}
			return fmt.Errorf("parse policy: keys %q and %q differ only by case", prev, key)
		}
		top.keys[folded] = key
		top.wantKey = false
		top.child = nil
		// A nil fields map accepts any key name (only duplicate and
		// case-colliding keys, checked above, are rejected): the asset
		// envelope uses it so a snake_case or future field passes while the
		// iam_policy value is still checked by its own schema.
		if top.schema != nil && top.schema.fields != nil {
			child, known := top.schema.fields[key]
			if !known {
				return fmt.Errorf("parse policy: unexpected key %q", key)
			}
			top.child = child
		}
	}
}
