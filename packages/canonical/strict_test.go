package canonical

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func nested(n int) string {
	return strings.Repeat("[", n) + "1" + strings.Repeat("]", n)
}

func TestScanDepth(t *testing.T) {
	if err := CheckStrictJSON([]byte(nested(16))); err != nil {
		t.Fatalf("depth 16 rejected: %v", err)
	}
	if err := CheckStrictJSON([]byte(nested(17))); err == nil {
		t.Fatal("depth 17 accepted")
	}
	obj := strings.Repeat(`{"a":`, 16) + "1" + strings.Repeat("}", 16)
	if err := CheckStrictJSON([]byte(obj)); err != nil {
		t.Fatalf("object depth 16 rejected: %v", err)
	}
	if err := CheckStrictJSON([]byte(`{"a":` + obj + `}`)); err == nil {
		t.Fatal("object depth 17 accepted")
	}
}

func TestScanKeyLength(t *testing.T) {
	ok := fmt.Sprintf(`{"%s":1}`, strings.Repeat("k", 128))
	if err := CheckStrictJSON([]byte(ok)); err != nil {
		t.Fatalf("128-byte key rejected: %v", err)
	}
	// 43 three-byte runes = 129 bytes.
	bad := fmt.Sprintf(`{"%s":1}`, strings.Repeat("가", 43))
	if err := CheckStrictJSON([]byte(bad)); err == nil {
		t.Fatal("129-byte key accepted")
	}
}

func TestScanNumbers(t *testing.T) {
	accept := []string{`[9007199254740991]`, `[-9007199254740991]`, `[0]`, `[-0]`}
	reject := []string{`[9007199254740992]`, `[-9007199254740992]`, `[1.0]`, `[1e2]`, `[1E2]`, `[NaN]`, `[Infinity]`, `[-Infinity]`, `[01]`, `[+1]`, `[0x10]`, `[99999999999999999999999]`}
	for _, s := range accept {
		if err := CheckStrictJSON([]byte(s)); err != nil {
			t.Errorf("%s rejected: %v", s, err)
		}
	}
	for _, s := range reject {
		if err := CheckStrictJSON([]byte(s)); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestScanStringsAndKeys(t *testing.T) {
	accept := []string{
		`{"a":"😂"}`,
		`{"a":"\\ud800"}`, // escaped backslash: literal text, not a surrogate escape
		`{"a":"\"\\\/\b\f\n\r\tA"}`,
		`{"a":1,"b":{"a":2}}`, // same key in different objects
		"{\"a\":\"\xed\x9f\xbf\"}",
	}
	reject := []string{
		`{"a":"\ud800"}`,
		`{"a":"\ud800A"}`,
		`{"a":"\udfff"}`,
		`{"a":"\ud83d\ud83d"}`,
		"{\"a\":\"\xed\xa0\x80\"}", // UTF-8 encoded surrogate is invalid UTF-8
		"{\"a\":\"\xff\"}",
		`{"a":1,"a":1}`,
		`{"ab":1,"AB":2}`,
		`{"a":1}{}`,
		`{"a":1} 1`,
		`{"a":1,}`,
		"\xef\xbb\xbf{}",
		``,
	}
	for _, s := range accept {
		if err := CheckStrictJSON([]byte(s)); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
	for _, s := range reject {
		if err := CheckStrictJSON([]byte(s)); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestCheckShape(t *testing.T) {
	type inner struct {
		X int64 `json:"x"`
	}
	type shape struct {
		A string  `json:"a"`
		B *string `json:"b"`
		C []inner `json:"c"`
	}
	cases := map[string]bool{
		`{"a":"x","b":null,"c":[]}`:          true,
		`{"a":"x","b":"y","c":[{"x":1}]}`:    true,
		`{"a":"x","b":null}`:                 false, // missing key
		`{"a":"x","b":null,"c":[],"d":1}`:    false, // unknown key
		`{"A":"x","b":null,"c":[]}`:          false, // tag case
		`{"a":null,"b":null,"c":[]}`:         false, // null for non-pointer
		`{"a":"x","b":null,"c":null}`:        false,
		`{"a":"x","b":null,"c":[{"X":1}]}`:   false,
		`{"a":1,"b":null,"c":[]}`:            false,
		`{"a":"x","b":null,"c":[{"x":"1"}]}`: false,
	}
	for in, want := range cases {
		root, err := scanJSON([]byte(in), clientScan)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		err = checkShape(root, reflect.TypeOf(shape{}), "$")
		if (err == nil) != want {
			t.Errorf("%s: err=%v want ok=%v", in, err, want)
		}
	}
}

func TestDecodeClientActionBodyLimit(t *testing.T) {
	big := []byte(`{"session_id":"` + strings.Repeat("a", MaxBodyBytes) + `"}`)
	_, err := DecodeClientAction(big)
	if err == nil || err.HTTPStatus != 413 || err.ReasonCodes[0] != ReasonBodyTooLarge || err.RuleID != "" {
		t.Fatalf("got %v", err)
	}
}

// Go encoding/json v1 alone would accept these; the pre-check must not.
func TestStdlibLeniencyIsBlocked(t *testing.T) {
	s := "51ab2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	cases := []string{
		// case-insensitive field match in v1
		`{"SESSION_ID":"` + s + `","operation_id":"k8s.pods.list","requested_target":{"target_id":"x"},"arguments":{},"client_request_key":"req-00000001"}`,
		// duplicate name, last wins in v1
		`{"session_id":"` + s + `","operation_id":"receiver.submit","operation_id":"k8s.pods.list","requested_target":{"target_id":"x"},"arguments":{},"client_request_key":"req-00000001"}`,
		// lone surrogate becomes U+FFFD in v1
		`{"session_id":"` + s + `","operation_id":"k8s.pods.list","requested_target":{"target_id":"x"},"arguments":{},"client_request_key":"req-0000\ud800"}`,
	}
	for _, c := range cases {
		if _, err := DecodeClientAction([]byte(c)); err == nil || err.HTTPStatus != 422 {
			t.Errorf("accepted or wrong status: %s -> %v", c, err)
		}
	}
}
