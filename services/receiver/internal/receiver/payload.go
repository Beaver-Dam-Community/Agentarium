package receiver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// MaxBodyBytes is the receiver.submit body limit. The receiver-sender adapter
// caps the same body at 64KiB (TASK-05 3.1); a larger body is answered with
// 413 BODY_TOO_LARGE before anything is recorded.
const MaxBodyBytes = 64 << 10

// validatePayload checks the catalog receiver payload schema on the raw body
// (TASK-02 3.2: summary 1..4096 bytes, email null or 3..254 bytes) with the
// COMMON strict JSON rules: canonical.CheckStrictJSON first (UTF-8,
// surrogates, duplicate and case-only duplicate keys, depth, key length,
// numbers), then exact keys and JSON types (encoding/json matches keys case-
// insensitively), then a json.Decoder with DisallowUnknownFields and
// UseNumber into canonical.ReceiverPayload. Both keys are required; email may
// be null.
func validatePayload(raw []byte) error {
	if err := canonical.CheckStrictJSON(raw); err != nil {
		return err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("payload must be an object: %w", err)
	}
	if obj == nil {
		return errors.New("payload must be an object")
	}
	for k := range obj {
		if k != "summary" && k != "email" {
			return fmt.Errorf("unknown key %q", k)
		}
	}
	summaryRaw, ok := obj["summary"]
	if !ok {
		return errors.New("missing key \"summary\"")
	}
	emailRaw, ok := obj["email"]
	if !ok {
		return errors.New("missing key \"email\"")
	}
	// encoding/json decodes null into a string as "", so the JSON types are
	// checked before the typed decode.
	if !isJSONString(summaryRaw) {
		return errors.New("summary: expected string")
	}
	if !isJSONString(emailRaw) && !bytes.Equal(bytes.TrimSpace(emailRaw), []byte("null")) {
		return errors.New("email: expected string or null")
	}

	// Second stage (COMMON Go strict JSON, TASK-08 2): typed decode with
	// DisallowUnknownFields and UseNumber.
	var p canonical.ReceiverPayload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if len(p.Summary) < 1 || len(p.Summary) > 4096 {
		return errors.New("summary must be 1..4096 bytes")
	}
	if p.Email != nil && (len(*p.Email) < 3 || len(*p.Email) > 254) {
		return errors.New("email must be null or 3..254 bytes")
	}
	return nil
}

func isJSONString(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '"'
}
