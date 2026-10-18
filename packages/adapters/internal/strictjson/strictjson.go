// Package strictjson decodes JSON the way COMMON "Go strict JSON" requires:
// the packages/canonical pre-check (UTF-8, surrogates, duplicate and
// case-only duplicate keys, depth, key length, integer range), object keys
// equal to the struct json tags exactly, then DisallowUnknownFields.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Decode decodes raw into v (a pointer to a struct). Every key without
// omitempty must be present; keys are matched case-sensitively.
func Decode(raw []byte, v any) error {
	if err := canonical.CheckStrictJSON(raw); err != nil {
		return err
	}
	t := reflect.TypeOf(v)
	if t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
		return errors.New("strictjson: v must point to a struct")
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return err
	}
	if keys == nil {
		return errors.New("strictjson: body is not an object")
	}
	allowed := map[string]bool{}
	st := t.Elem()
	for i := 0; i < st.NumField(); i++ {
		tag := st.Field(i).Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		allowed[name] = true
		if !strings.Contains(opts, "omitempty") {
			if _, ok := keys[name]; !ok {
				return fmt.Errorf("strictjson: missing field %q", name)
			}
		}
	}
	for k := range keys {
		if !allowed[k] {
			return fmt.Errorf("strictjson: unknown field %q", k)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("strictjson: trailing data")
	}
	return nil
}
