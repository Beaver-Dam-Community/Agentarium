package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"unicode/utf8"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical/internal/jcs"
)

// SHA256Hex returns the lowercase hex SHA-256 of b.
func SHA256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// JCS returns the RFC 8785 serialization of a JSON object or array given as
// bytes. Duplicate keys, invalid UTF-8, lone surrogates and non-finite numbers
// are rejected; the input must already be valid JSON (see CheckJSONForJCS).
func JCS(raw []byte) ([]byte, error) {
	if err := CheckJSONForJCS(raw); err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

// JCSLibrary is JCS without the integral-number range contract. It is only
// for checking the vendored serializer against RFC 8785 number vectors (1E30,
// 1e21) that no service input can contain; services and tools use JCS.
func JCSLibrary(raw []byte) ([]byte, error) {
	if err := checkJCSInput(raw, libraryJCSScan); err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

// CheckJSONForJCS validates JSON grammar, UTF-8, surrogates, exact duplicate
// keys, integer range ±(2^53-1) and finiteness. Fractions and exponents are
// allowed, but a number whose value is integral (100.0, 1e16) must also be
// within ±(2^53-1); there are no depth or key-length limits.
func CheckJSONForJCS(raw []byte) error {
	return checkJCSInput(raw, contractJCSScan)
}

// contractJCSScan is the scan used for every digest the services compute.
var contractJCSScan = scanOptions{integralRange: true}

// libraryJCSScan accepts any finite number. It exists only to check the JCS
// number serializer against RFC 8785 vectors such as 1E30 (TASK-02 3.3
// "decimal serialization (library verification only)"); no service input uses it.
var libraryJCSScan = scanOptions{}

func checkJCSInput(raw []byte, opt scanOptions) error {
	root, err := scanJSON(raw, opt)
	if err != nil {
		return err
	}
	if root.kind != kindObject && root.kind != kindArray {
		return errors.New("JCS input must be an object or array")
	}
	return nil
}

// CanonicalJSON marshals v and returns its JCS bytes. encoding/json replaces
// invalid UTF-8 in Go strings with U+FFFD, which would give different inputs
// the same digest, so every string and map key is checked first.
func CanonicalJSON(v any) ([]byte, error) {
	if err := checkUTF8Value(reflect.ValueOf(v), "$"); err != nil {
		return nil, err
	}
	b, err := marshalNoEscape(v)
	if err != nil {
		return nil, err
	}
	return JCS(b)
}

// CanonicalDigest is SHA-256(JCS(v)) in lowercase hex ("canonical digest", COMMON).
func CanonicalDigest(v any) (string, error) {
	c, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return SHA256Hex(c), nil
}

// CanonicalDigestJSON is the canonical digest of JSON given as bytes.
func CanonicalDigestJSON(raw []byte) (string, error) {
	c, err := JCS(raw)
	if err != nil {
		return "", err
	}
	return SHA256Hex(c), nil
}

// ActionDigest is canonical digest of the fixed 10-key hash object.
func ActionDigest(h HashObject) (string, error) {
	if h.DisclosureFields == nil || h.Limits == nil {
		return "", errors.New("disclosure_fields and limits must be non-nil")
	}
	return CanonicalDigest(h)
}

// RawBodyDigest is SHA-256 of the raw request body bytes (TASK-04).
func RawBodyDigest(raw []byte) string { return SHA256Hex(raw) }

// WireBodyDigest is SHA-256 of the bytes actually sent (TASK-05/08).
func WireBodyDigest(body []byte) string { return SHA256Hex(body) }

// ClientRequestKeyDigest is SHA-256(client_request_key).
func ClientRequestKeyDigest(key string) string { return SHA256Hex([]byte(key)) }

// TokenDigest is SHA-256(session token).
func TokenDigest(token string) string { return SHA256Hex([]byte(token)) }

// SortSet de-duplicates set elements and orders them by the byte order of
// each element's JCS serialization (TASK-02 3.3 "set ordering").
func SortSet[T any](elems []T) ([]T, error) {
	type item struct {
		key []byte
		v   T
	}
	items := make([]item, 0, len(elems))
	seen := map[string]bool{}
	for _, e := range elems {
		c, err := CanonicalJSON([]any{e})
		if err != nil {
			return nil, err
		}
		k := c[1 : len(c)-1]
		if seen[string(k)] {
			continue
		}
		seen[string(k)] = true
		items = append(items, item{k, e})
	}
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].key, items[j].key) < 0 })
	out := make([]T, len(items))
	for i, it := range items {
		out[i] = it.v
	}
	return out, nil
}

// DigestWithoutKeys is the canonical digest of a JSON object after removing
// the named top-level keys. It implements payload_digest (AuditEvent without
// payload_digest and received_at) and batch_digest (request without batch_digest).
func DigestWithoutKeys(rawObject []byte, drop ...string) (string, error) {
	if err := CheckJSONForJCS(rawObject); err != nil {
		return "", err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rawObject, &m); err != nil {
		return "", fmt.Errorf("expected a JSON object: %w", err)
	}
	for _, k := range drop {
		delete(m, k)
	}
	return CanonicalDigest(m)
}

// PayloadDigest implements AuditEvent payload_digest (COMMON).
func PayloadDigest(auditEvent []byte) (string, error) {
	return DigestWithoutKeys(auditEvent, "payload_digest", "received_at")
}

// BatchDigest implements kernel/lifecycle batch_digest (COMMON "API implementation contract").
func BatchDigest(batchRequest []byte) (string, error) {
	return DigestWithoutKeys(batchRequest, "batch_digest")
}

// FixtureRef is one entry of fixture_set_digest.
type FixtureRef struct {
	FixtureID     string `json:"fixture_id"`
	ContentDigest string `json:"content_digest"`
	Role          string `json:"role"`
}

// FixtureSetDigest is canonical digest of the fixture_id-sorted {fixture_id, content_digest, role} list.
func FixtureSetDigest(refs []FixtureRef) (string, error) {
	s := append([]FixtureRef(nil), refs...)
	sort.Slice(s, func(i, j int) bool { return s[i].FixtureID < s[j].FixtureID })
	for i := 1; i < len(s); i++ {
		if s[i].FixtureID == s[i-1].FixtureID {
			return "", fmt.Errorf("duplicate fixture_id %q", s[i].FixtureID)
		}
	}
	if s == nil {
		s = []FixtureRef{}
	}
	return CanonicalDigest(s)
}

// GovernanceRef is one entry of governance_map_digest refs.
type GovernanceRef struct {
	FixtureID      string   `json:"fixture_id"`
	GovernanceRefs []string `json:"governance_refs"`
}

// GovernanceMapDigest is canonical digest({ids_digest, refs}) with refs sorted by fixture_id.
// governance_refs order inside each entry is kept as given.
func GovernanceMapDigest(idsDigest string, refs []GovernanceRef) (string, error) {
	s := append([]GovernanceRef(nil), refs...)
	sort.Slice(s, func(i, j int) bool { return s[i].FixtureID < s[j].FixtureID })
	for i := range s {
		if s[i].GovernanceRefs == nil {
			s[i].GovernanceRefs = []string{}
		}
	}
	if s == nil {
		s = []GovernanceRef{}
	}
	return CanonicalDigest(struct {
		IDsDigest string          `json:"ids_digest"`
		Refs      []GovernanceRef `json:"refs"`
	}{idsDigest, s})
}

// checkUTF8Value walks v as encoding/json would and rejects any string or map
// key that is not valid UTF-8. json.RawMessage bytes are left to JCS, whose
// pre-scan checks the whole marshalled document.
func checkUTF8Value(v reflect.Value, path string) error {
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return checkUTF8Value(v.Elem(), path)
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return fmt.Errorf("%s: invalid UTF-8 in string", path)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() || f.Tag.Get("json") == "-" {
				continue
			}
			if err := checkUTF8Value(v.Field(i), path+"."+f.Name); err != nil {
				return err
			}
		}
	case reflect.Map:
		it := v.MapRange()
		for it.Next() {
			if k := it.Key(); k.Kind() == reflect.String && !utf8.ValidString(k.String()) {
				return fmt.Errorf("%s: invalid UTF-8 in map key", path)
			}
			if err := checkUTF8Value(it.Value(), fmt.Sprintf("%s[%v]", path, it.Key())); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return nil // []byte and json.RawMessage
		}
		for i := 0; i < v.Len(); i++ {
			if err := checkUTF8Value(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}
