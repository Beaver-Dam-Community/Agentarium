package canonical

import (
	"reflect"
	"testing"
)

func TestSortSet(t *testing.T) {
	got, err := SortSet([]string{"user", "system", "user", "tool_result", "Z"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Z", "system", "tool_result", "user"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Ordering is by JCS bytes: `"a"` (0x22...) sorts before `10` and `2`.
	got2, _ := SortSet([]any{"b", 2, "a", 10})
	if want := []any{"a", "b", 10, 2}; !reflect.DeepEqual(got2, want) {
		t.Fatalf("got %v want %v", got2, want)
	}
	empty, _ := SortSet([]string(nil))
	if len(empty) != 0 {
		t.Fatal("empty set")
	}
}

func TestCanonicalDigestKeyOrderAndWhitespace(t *testing.T) {
	a, err := CanonicalDigestJSON([]byte(`{"b":1,"a":[1,2]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := CanonicalDigestJSON([]byte(" {\n\"a\" : [1, 2], \"b\":1}\n"))
	c, _ := CanonicalDigestJSON([]byte(`{"a":[2,1],"b":1}`))
	if a != b || a == c {
		t.Fatalf("key order/whitespace must not matter, array order must: %s %s %s", a, b, c)
	}
	if _, err := CanonicalDigestJSON([]byte(`{"a":1,"a":1}`)); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestActionDigestRequiresNonNil(t *testing.T) {
	if _, err := ActionDigest(HashObject{}); err == nil {
		t.Fatal("nil disclosure_fields/limits accepted")
	}
	h := HashObject{DisclosureFields: []string{}, Limits: map[string]int64{}}
	b, err := CanonicalJSON(h)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"canonical_target":{"route_id":"","target_id":""},"canonicalization_version":"","catalog_digest":"","content_digest":null,"disclosure_fields":[],"environment":"","limits":{},"operation_id":"","schema_version":"","tenant":""}`
	if string(b) != want {
		t.Fatalf("hash object must have exactly the 10 keys with null content_digest:\n%s", b)
	}
}

func TestDigestWithoutKeys(t *testing.T) {
	ev1 := []byte(`{"event_id":"e1","payload_digest":"x","received_at":"2026-10-11T00:00:00Z","safe_payload":{"k":1}}`)
	ev2 := []byte(`{"safe_payload":{"k":1},"received_at":"2026-10-12T00:00:00Z","event_id":"e1","payload_digest":"y"}`)
	ev3 := []byte(`{"event_id":"e1","safe_payload":{"k":1}}`)
	d1, err := PayloadDigest(ev1)
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := PayloadDigest(ev2)
	d3, _ := CanonicalDigestJSON(ev3)
	if d1 != d2 || d1 != d3 {
		t.Fatalf("payload_digest must ignore payload_digest and received_at: %s %s %s", d1, d2, d3)
	}
	b1, _ := BatchDigest([]byte(`{"batch_id":"b","records":[],"batch_digest":"z"}`))
	b2, _ := CanonicalDigestJSON([]byte(`{"batch_id":"b","records":[]}`))
	if b1 != b2 {
		t.Fatal("batch_digest")
	}
	if _, err := PayloadDigest([]byte(`[1]`)); err == nil {
		t.Fatal("array accepted as object")
	}
}

func TestFixtureAndGovernanceDigests(t *testing.T) {
	a := []FixtureRef{{"f2", "d2", "required"}, {"f1", "d1", "holdout"}}
	b := []FixtureRef{{"f1", "d1", "holdout"}, {"f2", "d2", "required"}}
	da, err := FixtureSetDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := FixtureSetDigest(b)
	want, _ := CanonicalDigestJSON([]byte(`[{"fixture_id":"f1","content_digest":"d1","role":"holdout"},{"fixture_id":"f2","content_digest":"d2","role":"required"}]`))
	if da != db || da != want {
		t.Fatal("fixture_set_digest must sort by fixture_id")
	}
	if _, err := FixtureSetDigest([]FixtureRef{{"f1", "a", "required"}, {"f1", "b", "required"}}); err == nil {
		t.Fatal("duplicate fixture_id accepted")
	}
	g1, _ := GovernanceMapDigest("ids", []GovernanceRef{{"f2", []string{"G-2"}}, {"f1", nil}})
	g2, _ := GovernanceMapDigest("ids", []GovernanceRef{{"f1", []string{}}, {"f2", []string{"G-2"}}})
	g3, _ := GovernanceMapDigest("ids", []GovernanceRef{{"f1", []string{}}, {"f2", []string{"G-3"}}})
	gw, _ := CanonicalDigestJSON([]byte(`{"ids_digest":"ids","refs":[{"fixture_id":"f1","governance_refs":[]},{"fixture_id":"f2","governance_refs":["G-2"]}]}`))
	if g1 != g2 || g1 != gw || g1 == g3 {
		t.Fatal("governance_map_digest")
	}
}

func TestSimpleSHA256Digests(t *testing.T) {
	// SHA-256("") and SHA-256("abc") from FIPS 180-2.
	if RawBodyDigest(nil) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("empty")
	}
	if TokenDigest("abc") != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ||
		ClientRequestKeyDigest("abc") != TokenDigest("abc") || WireBodyDigest([]byte("abc")) != TokenDigest("abc") {
		t.Fatal("abc")
	}
}

// encoding/json would turn both strings into "a�"; CanonicalJSON must
// refuse instead of giving them one digest.
func TestCanonicalJSONRejectsInvalidUTF8(t *testing.T) {
	type inner struct {
		S string `json:"s"`
	}
	type doc struct {
		Name  string            `json:"name"`
		Tags  []string          `json:"tags"`
		Attrs map[string]string `json:"attrs"`
		Ptr   *inner            `json:"ptr"`
		Any   any               `json:"any"`
	}
	bad := "a\xff"
	cases := map[string]any{
		"field":      doc{Name: bad},
		"slice":      doc{Tags: []string{"ok", bad}},
		"map value":  doc{Attrs: map[string]string{"k": bad}},
		"map key":    doc{Attrs: map[string]string{bad: "v"}},
		"pointer":    doc{Ptr: &inner{S: bad}},
		"interface":  doc{Any: map[string]any{"x": []any{bad}}},
		"top string": []string{bad},
	}
	for name, v := range cases {
		if _, err := CanonicalJSON(v); err == nil {
			t.Errorf("%s: invalid UTF-8 accepted", name)
		}
		if _, err := CanonicalDigest(v); err == nil {
			t.Errorf("%s: CanonicalDigest accepted invalid UTF-8", name)
		}
	}
	if _, err := CanonicalJSON(doc{Name: "a�", Tags: []string{}, Attrs: map[string]string{}}); err != nil {
		t.Errorf("valid U+FFFD rejected: %v", err)
	}
}
