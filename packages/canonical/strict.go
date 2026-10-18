package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Strict input limits (TASK-02 3.1, COMMON "normalization and hashing").
const (
	MaxBodyBytes   = 1 << 20
	MaxDepth       = 16
	MaxKeyBytes    = 128
	MaxSafeInteger = 1<<53 - 1
)

type jsonKind int

const (
	kindNull jsonKind = iota
	kindBool
	kindNumber
	kindString
	kindArray
	kindObject
)

// jnode is the pre-scan tree. Object keys keep input order.
type jnode struct {
	kind  jsonKind
	num   string
	keys  []string
	vals  []*jnode
	elems []*jnode
}

type scanOptions struct {
	integersOnly       bool // reject fraction and exponent in number tokens
	integralRange      bool // a fraction/exponent literal with an integral value must be within ±(2^53-1)
	caseFoldDuplicates bool // reject keys equal under strings.ToLower
	maxDepth           int  // 0 means unlimited
	maxKeyBytes        int  // 0 means unlimited
}

// clientScan is the option set for request bodies (TASK-02 3.1 steps 2-4).
var clientScan = scanOptions{integersOnly: true, caseFoldDuplicates: true, maxDepth: MaxDepth, maxKeyBytes: MaxKeyBytes}

// scanJSON validates raw bytes before any encoding/json decoding.
// Depth counts open containers; the top-level container is depth 1.
// SPEC-QUESTION: TASK-02 3.1 says "count the top-level value as 1, at most 16"
// without saying
// whether scalar leaves count. Here only objects and arrays count.
func scanJSON(raw []byte, opt scanOptions) (*jnode, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("invalid UTF-8")
	}
	if err := checkSurrogateEscapes(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	s := &scanner{dec: dec, opt: opt}
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	root, err := s.value(tok, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after top-level value")
	}
	return root, nil
}

type scanner struct {
	dec *json.Decoder
	opt scanOptions
}

func (s *scanner) value(tok json.Token, depth int) (*jnode, error) {
	switch v := tok.(type) {
	case json.Delim:
		depth++
		if s.opt.maxDepth > 0 && depth > s.opt.maxDepth {
			return nil, fmt.Errorf("nesting depth exceeds %d", s.opt.maxDepth)
		}
		switch v {
		case '{':
			return s.object(depth)
		case '[':
			return s.array(depth)
		}
		return nil, fmt.Errorf("unexpected delimiter %q", v)
	case string:
		return &jnode{kind: kindString}, nil
	case json.Number:
		if err := s.number(string(v)); err != nil {
			return nil, err
		}
		return &jnode{kind: kindNumber, num: string(v)}, nil
	case bool:
		return &jnode{kind: kindBool}, nil
	case nil:
		return &jnode{kind: kindNull}, nil
	}
	return nil, fmt.Errorf("unexpected token %T", tok)
}

func (s *scanner) object(depth int) (*jnode, error) {
	n := &jnode{kind: kindObject}
	exact := map[string]bool{}
	folded := map[string]bool{}
	for {
		tok, err := s.dec.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			return n, nil
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		if s.opt.maxKeyBytes > 0 && len(key) > s.opt.maxKeyBytes {
			return nil, fmt.Errorf("key longer than %d bytes", s.opt.maxKeyBytes)
		}
		if exact[key] {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		exact[key] = true
		if s.opt.caseFoldDuplicates {
			lk := strings.ToLower(key)
			if folded[lk] {
				return nil, fmt.Errorf("case-insensitive duplicate key %q", key)
			}
			folded[lk] = true
		}
		vt, err := s.dec.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		child, err := s.value(vt, depth)
		if err != nil {
			return nil, err
		}
		n.keys = append(n.keys, key)
		n.vals = append(n.vals, child)
	}
}

func (s *scanner) array(depth int) (*jnode, error) {
	n := &jnode{kind: kindArray}
	for {
		tok, err := s.dec.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		if d, ok := tok.(json.Delim); ok && d == ']' {
			return n, nil
		}
		child, err := s.value(tok, depth)
		if err != nil {
			return nil, err
		}
		n.elems = append(n.elems, child)
	}
}

func (s *scanner) number(lit string) error {
	isInt := !strings.ContainsAny(lit, ".eE")
	if !isInt {
		if s.opt.integersOnly {
			return fmt.Errorf("non-integer number %s", lit)
		}
		f, err := strconv.ParseFloat(lit, 64)
		if err != nil || math.IsInf(f, 0) {
			return fmt.Errorf("number out of range %s", lit)
		}
		// 9007199254740993.0 and 9007199254740992 serialize identically under
		// RFC 8785 (both become 9007199254740992), so an integral value written
		// with a fraction or exponent gets the same ±(2^53-1) contract as an
		// integer token (TASK-02 3.1 step 4, COMMON integer range).
		if s.opt.integralRange {
			r, ok := new(big.Rat).SetString(lit)
			if !ok {
				return fmt.Errorf("invalid number %s", lit)
			}
			if r.IsInt() && new(big.Int).Abs(r.Num()).Cmp(big.NewInt(MaxSafeInteger)) > 0 {
				return fmt.Errorf("integral number outside ±(2^53-1): %s", lit)
			}
		}
		return nil
	}
	v, err := strconv.ParseInt(lit, 10, 64)
	if err != nil || v > MaxSafeInteger || v < -MaxSafeInteger {
		return fmt.Errorf("integer outside ±(2^53-1): %s", lit)
	}
	return nil
}

// checkSurrogateEscapes rejects \uD800-\uDBFF not followed by \uDC00-\uDFFF and
// lone \uDC00-\uDFFF, reading escapes directly from raw bytes.
func checkSurrogateEscapes(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(raw) {
				return errors.New("truncated escape")
			}
			if raw[i+1] != 'u' {
				i++
				continue
			}
			u, ok := hex4(raw, i+2)
			if !ok {
				return errors.New("invalid \\u escape")
			}
			switch {
			case u >= 0xD800 && u <= 0xDBFF:
				if i+11 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
					return errors.New("unpaired high surrogate")
				}
				lo, ok := hex4(raw, i+8)
				if !ok || lo < 0xDC00 || lo > 0xDFFF {
					return errors.New("unpaired high surrogate")
				}
				i += 11
			case u >= 0xDC00 && u <= 0xDFFF:
				return errors.New("unpaired low surrogate")
			default:
				i += 5
			}
		}
	}
	return nil
}

func hex4(b []byte, at int) (rune, bool) {
	if at+4 > len(b) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(b[at:at+4]), 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(v), true
}

var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

// checkShape enforces that every object key equals a json tag of the target
// struct exactly (case-sensitive), that every tag is present, and that null
// appears only where the Go type is a pointer. json.RawMessage must be an object.
// SPEC-QUESTION: 3.1 step 5 requires exact key match but does not say whether a
// key may be omitted. All keys are required here; nullable fields are sent as null.
func checkShape(n *jnode, t reflect.Type, path string) error {
	if t == rawMessageType {
		if n.kind != kindObject {
			return fmt.Errorf("%s: expected object", path)
		}
		return nil
	}
	if t.Kind() == reflect.Pointer {
		if n.kind == kindNull {
			return nil
		}
		return checkShape(n, t.Elem(), path)
	}
	if n.kind == kindNull {
		return fmt.Errorf("%s: null not allowed", path)
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.kind != kindObject {
			return fmt.Errorf("%s: expected object", path)
		}
		fields := map[string]reflect.Type{}
		optional := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			fields[name] = f.Type
			optional[name] = f.Tag.Get("canonical") == "optional"
		}
		seen := 0
		for i, k := range n.keys {
			ft, ok := fields[k]
			if !ok {
				return fmt.Errorf("%s: unknown key %q", path, k)
			}
			seen++
			if err := checkShape(n.vals[i], ft, path+"."+k); err != nil {
				return err
			}
		}
		if seen != len(fields) {
			for name := range fields {
				if !contains(n.keys, name) {
					// Optional shape fields can still be required by operation validation.
					if optional[name] {
						continue
					}
					return fmt.Errorf("%s: missing key %q", path, name)
				}
			}
		}
	case reflect.Slice:
		if n.kind != kindArray {
			return fmt.Errorf("%s: expected array", path)
		}
		for i, e := range n.elems {
			if err := checkShape(e, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case reflect.String:
		if n.kind != kindString {
			return fmt.Errorf("%s: expected string", path)
		}
	case reflect.Int64:
		if n.kind != kindNumber {
			return fmt.Errorf("%s: expected integer", path)
		}
	case reflect.Bool:
		if n.kind != kindBool {
			return fmt.Errorf("%s: expected boolean", path)
		}
	default:
		return fmt.Errorf("%s: unsupported type %s", path, t)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// decodeStrict runs the full 3.1 procedure for one typed value: pre-scan,
// exact key/shape check against v's type, then DisallowUnknownFields+UseNumber decode.
func decodeStrict(raw []byte, v any) error {
	root, err := scanJSON(raw, clientScan)
	if err != nil {
		return err
	}
	if err := checkShape(root, reflect.TypeOf(v).Elem(), "$"); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// CheckStrictJSON applies the request-body pre-check (UTF-8, surrogates,
// duplicate and case-only duplicate keys, depth, key length, integer-only
// numbers within ±(2^53-1), no trailing tokens) to arbitrary JSON.
func CheckStrictJSON(raw []byte) error {
	_, err := scanJSON(raw, clientScan)
	return err
}
