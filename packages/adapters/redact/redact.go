// Package redact removes catalog redact_fields from a response document
// (TASK-05 3.4 sanitization). Each field is a JSON Pointer (RFC 6901); the token "*"
// stands for every element of an array, for example
// /items/*/metadata/managedFields.
package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// JSON decodes raw, removes every pointer and returns the re-encoded document.
// Numbers keep their literal form (UseNumber). A pointer that matches nothing
// is not an error.
func JSON(raw []byte, pointers []string) ([]byte, error) {
	if len(pointers) == 0 {
		return raw, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	for _, p := range pointers {
		toks, err := parse(p)
		if err != nil {
			return nil, err
		}
		if len(toks) == 0 {
			return nil, fmt.Errorf("redact: pointer %q removes the whole document", p)
		}
		doc = remove(doc, toks)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func parse(p string) ([]string, error) {
	if p == "" {
		return nil, nil
	}
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("redact: %q is not a JSON Pointer", p)
	}
	parts := strings.Split(p[1:], "/")
	for i, t := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
	}
	return parts, nil
}

// remove deletes the location toks names inside v and returns v.
func remove(v any, toks []string) any {
	tok, rest := toks[0], toks[1:]
	switch n := v.(type) {
	case map[string]any:
		if len(rest) == 0 {
			delete(n, tok)
			return n
		}
		if child, ok := n[tok]; ok {
			n[tok] = remove(child, rest)
		}
		return n
	case []any:
		if tok == "*" {
			if len(rest) == 0 {
				return []any{}
			}
			for i := range n {
				n[i] = remove(n[i], rest)
			}
			return n
		}
		i, err := strconv.Atoi(tok)
		if err != nil || i < 0 || i >= len(n) || strconv.Itoa(i) != tok {
			return n
		}
		if len(rest) == 0 {
			return append(n[:i:i], n[i+1:]...)
		}
		n[i] = remove(n[i], rest)
		return n
	default:
		return v
	}
}
