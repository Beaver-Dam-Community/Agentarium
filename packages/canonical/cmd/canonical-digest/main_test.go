package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(args []string, in string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(in), &out, &errb)
	return code, out.String(), errb.String()
}

func TestDigestAndJCS(t *testing.T) {
	in := `{"b": [1, 0.5, 1.5e-7], "a": "é"}`
	code, out, _ := runCLI(nil, in)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	code, jcs, _ := runCLI([]string{"-mode", "jcs"}, in)
	if code != 0 || jcs != `{"a":"é","b":[1,0.5,1.5e-7]}` {
		t.Fatalf("jcs %q (%d)", jcs, code)
	}
	// An integral value beyond ±(2^53-1) is rejected whatever its notation.
	if code, out, _ := runCLI(nil, `{"b":[1e21]}`); code != 1 || out != "" {
		t.Fatalf("1e21: exit %d stdout %q", code, out)
	}
	if len(out) != 65 || out[64] != '\n' {
		t.Fatalf("digest output %q", out)
	}
}

func TestRejects(t *testing.T) {
	for _, in := range []string{`{"a":1,"a":2}`, `{"a":"\ud800"}`, `"x"`, `{"a":9007199254740992}`, `{} {}`, `{"a":NaN}`, "{\"a\":\"\xff\"}", ``} {
		code, out, errs := runCLI(nil, in)
		if code != 1 || out != "" || errs == "" {
			t.Errorf("%q: exit %d out %q", in, code, out)
		}
	}
	if code, _, _ := runCLI([]string{"-mode", "hex"}, `{}`); code != 2 {
		t.Errorf("bad mode exit %d", code)
	}
	if code, _, _ := runCLI([]string{"extra"}, `{}`); code != 2 {
		t.Errorf("extra arg exit %d", code)
	}
}

// The CLI must agree with the shared vectors (values computed by the JS reference).
func TestSharedJCSVectors(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		JCS []struct {
			ID             string `json:"id"`
			Input          string `json:"input"`
			ExpectedJCS    string `json:"expected_jcs"`
			ExpectedSHA256 string `json:"expected_sha256"`
			LibraryOnly    bool   `json:"library_only"`
		} `json:"jcs"`
		JCSReject []struct {
			ID    string `json:"id"`
			Input string `json:"input"`
		} `json:"jcs_reject"`
		Catalog struct {
			JSONValue     json.RawMessage `json:"json_value"`
			CatalogDigest string          `json:"catalog_digest"`
		} `json:"catalog"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.JCS {
		if c.LibraryOnly {
			// Serializer-only vectors (1E30) break the ±(2^53-1) contract the
			// CLI enforces for every digest it computes.
			if code, _, _ := runCLI(nil, c.Input); code != 1 {
				t.Errorf("%s: library-only vector exit %d, want 1", c.ID, code)
			}
			continue
		}
		code, out, errs := runCLI(nil, c.Input)
		if code != 0 || out != c.ExpectedSHA256+"\n" {
			t.Errorf("%s: %d %q %s", c.ID, code, out, errs)
		}
		if _, j, _ := runCLI([]string{"-mode", "jcs"}, c.Input); j != c.ExpectedJCS {
			t.Errorf("%s: jcs %q", c.ID, j)
		}
	}
	for _, c := range v.JCSReject {
		if c.Input == "" {
			continue // hex-only vectors
		}
		if code, out, _ := runCLI(nil, c.Input); code != 1 || out != "" {
			t.Errorf("%s: exit %d stdout %q, want 1 and nothing", c.ID, code, out)
		}
	}
	if _, out, _ := runCLI(nil, string(v.Catalog.JSONValue)); out != v.Catalog.CatalogDigest+"\n" {
		t.Errorf("catalog_digest via CLI %q", out)
	}
}

// Builds and runs the real binary once to check stdin/stdout/exit behavior.
func TestBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	bin := filepath.Join(t.TempDir(), "canonical-digest")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(`{"a":1}`)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	// SHA-256 of `{"a":1}`.
	if string(out) != "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862\n" {
		t.Fatalf("got %q", out)
	}
	cmd = exec.Command(bin)
	cmd.Stdin = strings.NewReader(`{"a":1,"a":1}`)
	if err := cmd.Run(); err == nil {
		t.Fatal("duplicate key accepted")
	} else if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
		t.Fatalf("exit %v", err)
	}
}
