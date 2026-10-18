// Package contracts holds the cross-binary contract test of TASK-02 section 7
// "implementation agreement": the gateway and adapter binaries must produce the same
// action_digest and wire_body_digest for packages/canonical/testdata/vectors.json.
//
// Binaries are given by environment variables; the test skips when neither is set:
//
//	AGENTARIUM_GATEWAY_BIN=/path/to/gateway AGENTARIUM_ADAPTER_BIN=/path/to/adapter go test ./tests/contracts/
//
// SPEC-QUESTION: no Task defines how a service binary exposes this check. The
// harness assumes this invocation, which TASK-04/TASK-05 binaries must implement:
//
//	<bin> canonical-vectors <absolute path of vectors.json>
//
// The binary loads the catalog from the vectors file's catalog.dir (relative to
// the vectors file), sets ModelProfiles from model_profiles, builds each
// TrustedContext from trusted_default plus trusted_override, normalizes every
// entry of "normalize" with its own code path, and writes to stdout. A case
// with "catalog_variant" uses the base catalog with
// targets[catalog_variants[i].target_id].origin replaced by
// catalog_variants[i].origin and catalog_digest recomputed (same
// catalog_version), so a changed catalog must change action_digest:
//
//	{"results":[{"id":"<case id>","action_digest":"<hex>"|null,"wire_body_digest":"<hex>"|null}, ...]}
//
// with null digests for rejected cases. Exit status 0 means the run completed.
package contracts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

type vectorCase struct {
	ID     string `json:"id"`
	Expect struct {
		HTTPStatus     int     `json:"http_status"`
		ActionDigest   string  `json:"action_digest"`
		WireBodyDigest *string `json:"wire_body_digest"`
	} `json:"expect"`
}

type result struct {
	ID             string  `json:"id"`
	ActionDigest   *string `json:"action_digest"`
	WireBodyDigest *string `json:"wire_body_digest"`
}

func vectorsPath(t *testing.T) string {
	_, file, _, _ := runtime.Caller(0)
	p, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", "..", "packages", "canonical", "testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func loadCases(t *testing.T, path string) []vectorCase {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Normalize []vectorCase `json:"normalize"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Normalize) == 0 {
		t.Fatal("no normalize vectors")
	}
	return v.Normalize
}

func runBinary(t *testing.T, bin, vectors string) map[string]result {
	t.Helper()
	out, err := exec.Command(bin, "canonical-vectors", vectors).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("%s: %v\n%s", bin, err, ee.Stderr)
		}
		t.Fatalf("%s: %v", bin, err)
	}
	var doc struct {
		Results []result `json:"results"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("%s: stdout is not the expected JSON: %v", bin, err)
	}
	m := map[string]result{}
	for _, r := range doc.Results {
		if _, dup := m[r.ID]; dup {
			t.Fatalf("%s: duplicate result id %s", bin, r.ID)
		}
		m[r.ID] = r
	}
	return m
}

func str(p *string) string {
	if p == nil {
		return "null"
	}
	return *p
}

// compare checks both binaries against each other and against the vectors.
func compare(t *testing.T, cases []vectorCase, a, b map[string]result, nameA, nameB string) {
	for _, c := range cases {
		ra, okA := a[c.ID]
		rb, okB := b[c.ID]
		if !okA || !okB {
			t.Errorf("%s: missing result (%s=%v, %s=%v)", c.ID, nameA, okA, nameB, okB)
			continue
		}
		if str(ra.ActionDigest) != str(rb.ActionDigest) {
			t.Errorf("%s: action_digest differs: %s=%s %s=%s", c.ID, nameA, str(ra.ActionDigest), nameB, str(rb.ActionDigest))
		}
		if str(ra.WireBodyDigest) != str(rb.WireBodyDigest) {
			t.Errorf("%s: wire_body_digest differs: %s=%s %s=%s", c.ID, nameA, str(ra.WireBodyDigest), nameB, str(rb.WireBodyDigest))
		}
		if c.Expect.HTTPStatus != 0 {
			if ra.ActionDigest != nil {
				t.Errorf("%s: rejected vector produced an action_digest", c.ID)
			}
			continue
		}
		if str(ra.ActionDigest) != c.Expect.ActionDigest {
			t.Errorf("%s: action_digest %s, vectors %s", c.ID, str(ra.ActionDigest), c.Expect.ActionDigest)
		}
		if c.Expect.WireBodyDigest != nil && str(ra.WireBodyDigest) != *c.Expect.WireBodyDigest {
			t.Errorf("%s: wire_body_digest %s, vectors %s", c.ID, str(ra.WireBodyDigest), *c.Expect.WireBodyDigest)
		}
	}
}

func TestGatewayAdapterDigestParity(t *testing.T) {
	gw, ad := os.Getenv("AGENTARIUM_GATEWAY_BIN"), os.Getenv("AGENTARIUM_ADAPTER_BIN")
	if gw == "" && ad == "" {
		t.Skip("AGENTARIUM_GATEWAY_BIN and AGENTARIUM_ADAPTER_BIN not set; gateway/adapter binaries not provided")
	}
	if gw == "" || ad == "" {
		t.Fatal("set both AGENTARIUM_GATEWAY_BIN and AGENTARIUM_ADAPTER_BIN")
	}
	path := vectorsPath(t)
	cases := loadCases(t, path)
	compare(t, cases, runBinary(t, gw, path), runBinary(t, ad, path), "gateway", "adapter")
}

// Self-test of the harness with a reference binary built from packages/canonical.
// It checks the protocol and comparison logic only; it is not the gateway/adapter contract.
func TestHarnessWithReferenceBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	bin := filepath.Join(t.TempDir(), "refimpl")
	_, file, _, _ := runtime.Caller(0)
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/refimpl")
	cmd.Dir = filepath.Dir(file)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build refimpl: %v\n%s", err, out)
	}
	path := vectorsPath(t)
	cases := loadCases(t, path)
	ref := runBinary(t, bin, path)
	compare(t, cases, ref, ref, "ref", "ref")

	// The comparison must catch a divergent binary.
	bad := map[string]result{}
	for k, v := range ref {
		bad[k] = v
	}
	for _, c := range cases {
		if c.Expect.HTTPStatus == 0 {
			x := "0000000000000000000000000000000000000000000000000000000000000000"
			r := bad[c.ID]
			r.ActionDigest = &x
			bad[c.ID] = r
			break
		}
	}
	if n := countMismatches(cases, ref, bad); n == 0 {
		t.Fatal("harness did not detect a divergent action_digest")
	}
}

func countMismatches(cases []vectorCase, a, b map[string]result) int {
	n := 0
	for _, c := range cases {
		if str(a[c.ID].ActionDigest) != str(b[c.ID].ActionDigest) || str(a[c.ID].WireBodyDigest) != str(b[c.ID].WireBodyDigest) {
			n++
		}
	}
	return n
}
