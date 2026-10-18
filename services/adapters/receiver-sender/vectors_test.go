package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The canonical-vectors subcommand reproduces every expected action_digest and
// receiver wire_body_digest of packages/canonical/testdata/vectors.json.
func TestCanonicalVectors(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "packages", "canonical", "testdata", "vectors.json")
	var out bytes.Buffer
	if err := runVectors(path, &out); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Results []struct {
			ID             string  `json:"id"`
			ActionDigest   *string `json:"action_digest"`
			WireBodyDigest *string `json:"wire_body_digest"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Normalize []struct {
			ID     string `json:"id"`
			Expect struct {
				HTTPStatus     int     `json:"http_status"`
				ActionDigest   string  `json:"action_digest"`
				WireBodyDigest *string `json:"wire_body_digest"`
			} `json:"expect"`
		} `json:"normalize"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != len(v.Normalize) {
		t.Fatalf("%d results for %d vectors", len(got.Results), len(v.Normalize))
	}
	wires := 0
	for i, c := range v.Normalize {
		r := got.Results[i]
		if r.ID != c.ID {
			t.Fatalf("result %d is %s, want %s", i, r.ID, c.ID)
		}
		if c.Expect.HTTPStatus != 0 {
			if r.ActionDigest != nil {
				t.Errorf("%s: rejected vector produced a digest", c.ID)
			}
			continue
		}
		if r.ActionDigest == nil || *r.ActionDigest != c.Expect.ActionDigest {
			t.Errorf("%s: action_digest %v, want %s", c.ID, r.ActionDigest, c.Expect.ActionDigest)
		}
		if c.Expect.WireBodyDigest != nil {
			wires++
			if r.WireBodyDigest == nil || *r.WireBodyDigest != *c.Expect.WireBodyDigest {
				t.Errorf("%s: wire_body_digest %v, want %s", c.ID, r.WireBodyDigest, *c.Expect.WireBodyDigest)
			}
		}
	}
	if wires == 0 {
		t.Fatal("no wire_body_digest vector was checked")
	}
}
