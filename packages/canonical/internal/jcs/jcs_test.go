package jcs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Upstream testdata (identical to the RFC 8785 examples): input -> output and outhex.
func TestUpstreamTestdata(t *testing.T) {
	files, err := filepath.Glob("testdata/input/*.json")
	if err != nil || len(files) != 6 {
		t.Fatalf("expected 6 upstream inputs, got %d (%v)", len(files), err)
	}
	for _, in := range files {
		name := filepath.Base(in)
		t.Run(name, func(t *testing.T) {
			input := mustRead(t, in)
			want := mustRead(t, filepath.Join("testdata/output", name))
			hexWant := mustRead(t, filepath.Join("testdata/outhex", strings.TrimSuffix(name, ".json")+".txt"))
			got, err := Transform(input)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("vendored output mismatch\n got %q\nwant %q", got, want)
			}
			wantFromHex, err := hex.DecodeString(strings.Join(strings.Fields(string(hexWant)), ""))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, wantFromHex) {
				t.Fatalf("outhex mismatch")
			}
			again, err := Transform(got)
			if err != nil || !bytes.Equal(again, got) {
				t.Fatalf("not idempotent: %q %v", again, err)
			}
			ref, err := refCanonicalize(input)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ref, got) {
				t.Fatalf("reference mismatch\n ref %q\n got %q", ref, got)
			}
		})
	}
}

// RFC 8785 section 3.2.4: UTF-8 bytes of the section 3.2.2 sample.
func TestRFC8785Section324Bytes(t *testing.T) {
	const rfcHex = `
7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72
75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a
5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31
65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37
5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30
30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d`
	want, err := hex.DecodeString(strings.Join(strings.Fields(rfcHex), ""))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Transform(mustRead(t, "testdata/input/values.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// RFC 8785 Appendix B number serialization samples.
func TestRFC8785AppendixBNumbers(t *testing.T) {
	cases := []struct{ ieee, want string }{
		{"0000000000000000", "0"},
		{"8000000000000000", "0"},
		{"0000000000000001", "5e-324"},
		{"8000000000000001", "-5e-324"},
		{"7fefffffffffffff", "1.7976931348623157e+308"},
		{"ffefffffffffffff", "-1.7976931348623157e+308"},
		{"4340000000000000", "9007199254740992"},
		{"c340000000000000", "-9007199254740992"},
		{"4430000000000000", "295147905179352830000"},
		{"7fffffffffffffff", ""}, // NaN
		{"7ff0000000000000", ""}, // Infinity
		{"44b52d02c7e14af5", "9.999999999999997e+22"},
		{"44b52d02c7e14af6", "1e+23"},
		{"44b52d02c7e14af7", "1.0000000000000001e+23"},
		{"444b1ae4d6e2ef4e", "999999999999999700000"},
		{"444b1ae4d6e2ef4f", "999999999999999900000"},
		{"444b1ae4d6e2ef50", "1e+21"},
		{"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
		{"3eb0c6f7a0b5ed8d", "0.000001"},
		{"41b3de4355555553", "333333333.3333332"},
		{"41b3de4355555554", "333333333.33333325"},
		{"41b3de4355555555", "333333333.3333333"},
		{"41b3de4355555556", "333333333.3333334"},
		{"41b3de4355555557", "333333333.33333343"},
		{"becbf647612f3696", "-0.0000033333333333333333"},
		{"43143ff3c1cb0959", "1424953923781206.2"},
	}
	for _, c := range cases {
		bits, err := strconv.ParseUint(c.ieee, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		f := math.Float64frombits(bits)
		got, err := NumberToJSON(f)
		ref, refErr := refNumber(f)
		if c.want == "" {
			if err == nil || refErr == nil {
				t.Errorf("%s: expected error, got %q / %q", c.ieee, got, ref)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: vendored %q (%v), want %q", c.ieee, got, err, c.want)
		}
		if refErr != nil || ref != c.want {
			t.Errorf("%s: reference %q (%v), want %q", c.ieee, ref, refErr, c.want)
		}
	}
}

// Upstream ES6 number sequence checked against the SHA-256 table in
// upstream testdata/README.md (computed by the upstream JS generator).
func TestES6NumberSequence(t *testing.T) {
	expected := map[int]string{
		1000:    "be18b62b6f69cdab33a7e0dae0d9cfa869fda80ddc712221570f9f40a5878687",
		10000:   "b9f7a8e75ef22a835685a52ccba7f7d6bdc99e34b010992cbc5864cd12be6892",
		100000:  "22776e6d4b49fa294a0d0f349268e5c28808fe7e0cb2bcbe28f63894e494d4c7",
		1000000: "49415fee2c56c77864931bd3624faad425c3c577d6d74e89a83bc725506dad16",
	}
	limit := 1000000
	if testing.Short() {
		limit = 100000
	}
	next := numgen()
	hVendored, hRef := sha256.New(), sha256.New()
	var line []byte
	for n := 1; n <= limit; n++ {
		f := next()
		s, err := NumberToJSON(f)
		if err != nil {
			t.Fatalf("line %d: %v", n, err)
		}
		r, err := refNumber(f)
		if err != nil {
			t.Fatalf("line %d: %v", n, err)
		}
		if r != s {
			t.Fatalf("line %d (%x): vendored %q reference %q", n, math.Float64bits(f), s, r)
		}
		prefix := strconv.AppendUint(line[:0], math.Float64bits(f), 16)
		prefix = append(prefix, ',')
		hVendored.Write(append(append(prefix, s...), '\n'))
		hRef.Write(append(append(prefix[:len(prefix):len(prefix)], r...), '\n'))
		if want, ok := expected[n]; ok {
			if got := hex.EncodeToString(hVendored.Sum(nil)); got != want {
				t.Fatalf("first %d lines: vendored sha256 %s want %s", n, got, want)
			}
			if got := hex.EncodeToString(hRef.Sum(nil)); got != want {
				t.Fatalf("first %d lines: reference sha256 %s want %s", n, got, want)
			}
		}
	}
}

// Keys outside the BMP sort by UTF-16 code units, which differs from code point order.
func TestNonBMPKeyOrder(t *testing.T) {
	cases := []struct{ in, want string }{
		// U+1F602 (D83D DE02) sorts before U+FB33 in UTF-16 but after it by code point.
		{`{"\ufb33":2,"\ud83d\ude02":1,"a":3}`, "{\"a\":3,\"\U0001F602\":1,\"\uFB33\":2}"},
		// U+10000 (D800 DC00) sorts before U+FFFF.
		{`{"\uffff":"bmp","\ud800\udc00":"astral"}`, "{\"\U00010000\":\"astral\",\"\uFFFF\":\"bmp\"}"},
		// Raw UTF-8 input gives the same result as escapes.
		{"{\"\uFFFF\":\"bmp\",\"\U00010000\":\"astral\"}", "{\"\U00010000\":\"astral\",\"\uFFFF\":\"bmp\"}"},
	}
	for _, c := range cases {
		got, err := Transform([]byte(c.in))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.want {
			t.Errorf("vendored %q want %q", got, c.want)
		}
		ref, err := refCanonicalize([]byte(c.in))
		if err != nil {
			t.Fatal(err)
		}
		if string(ref) != c.want {
			t.Errorf("reference %q want %q", ref, c.want)
		}
	}
}

func TestCrossCheckCorpus(t *testing.T) {
	corpus := []string{
		`{"b":[1,2,{"z":null,"a":false}],"a":"x"}`,
		`[{"k":"\u0000\u001f\u007f"},"\t\"\\"]`,
		`{"n":[0,-0,1e21,1e-7,123456789012345680000,0.1,-1.5e-10,9007199254740991]}`,
		`{"e":{},"a":[],"s":"\u00e9\u0301"}`,
		`{"\u00e9":1,"e\u0301":2,"E":3,"e":4}`,
	}
	for _, in := range corpus {
		got, err := Transform([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		ref, err := refCanonicalize([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, ref) {
			t.Errorf("%s:\n vendored %q\nreference %q", in, got, ref)
		}
	}
}

func TestRejects(t *testing.T) {
	cases := map[string][]byte{
		"duplicate key":       []byte(`{"a":1,"a":2}`),
		"lone high surrogate": []byte(`{"a":"\ud800"}`),
		"lone low surrogate":  []byte(`{"a":"\udc00x"}`),
		"reversed pair":       []byte(`{"a":"\udc00\ud800"}`),
		"invalid utf8":        {'{', '"', 'a', '"', ':', '"', 0xc3, 0x28, '"', '}'},
		"NaN literal":         []byte(`{"a":NaN}`),
		"Infinity literal":    []byte(`{"a":Infinity}`),
		"top-level scalar":    []byte(`"x"`),
		"trailing garbage":    []byte(`{} x`),
	}
	for name, in := range cases {
		if got, err := Transform(in); err == nil {
			t.Errorf("%s: accepted, got %q", name, got)
		}
	}
}

// Documents that Transform is not a validating parser; callers must pre-check.
func TestTransformIsNotAValidatingParser(t *testing.T) {
	got, err := Transform([]byte(`[0x1p4]`))
	if err != nil {
		t.Skipf("upstream now rejects hex floats: %v", err)
	}
	if string(got) != "[16]" {
		t.Fatalf("unexpected %q", got)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
