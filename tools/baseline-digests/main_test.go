package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fixtureDir  = "../../packages/baseline/testdata/observation"
	goldenPath  = "../../packages/baseline/testdata/golden.json"
	exampleLock = "../../deploy/gcp/environment.lock.example.json"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestFromDirStdoutMatchesGolden(t *testing.T) {
	code, out, stderr := runCLI(t, "--from-dir", fixtureDir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Fatalf("stdout\n%s\nwant\n%s", out, want)
	}
}

func TestWriteLockReplacesOnlyBaselineDigests(t *testing.T) {
	orig, err := os.ReadFile(exampleLock)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(t.TempDir(), "environment.lock.json")
	if err := os.WriteFile(lock, orig, 0o640); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := runCLI(t, "--from-dir", fixtureDir, "--write-lock", lock)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if out != "" {
		t.Fatalf("stdout not empty with --write-lock: %q", out)
	}
	got, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}

	var golden map[string]string
	gb, _ := os.ReadFile(goldenPath)
	if err := json.Unmarshal(gb, &golden); err != nil {
		t.Fatal(err)
	}
	// The rewrite re-indents the whole file with two spaces, so compare
	// against the example with the six placeholder values replaced and the
	// same re-indent applied (inline arrays in the example become multi-line).
	want := string(orig)
	for _, k := range []string{"admission", "exec_rbac", "network_policy", "node_pool_config", "sensor_policy", "sensor_release_policies"} {
		old := `"` + k + `": "REPLACE_WITH_INSTALLER_GENERATED_SHA256"`
		if !strings.Contains(want, old) {
			t.Fatalf("example lock lacks %s", old)
		}
		want = strings.Replace(want, old, `"`+k+`": "`+golden[k]+`"`, 1)
	}
	var compact, indented bytes.Buffer
	if err := json.Compact(&compact, []byte(want)); err != nil {
		t.Fatal(err)
	}
	if err := json.Indent(&indented, compact.Bytes(), "", "  "); err != nil {
		t.Fatal(err)
	}
	want = indented.String() + "\n"
	if string(got) != want {
		t.Fatalf("lock rewrite changed more than baseline_digests:\n%s", got)
	}
	if st, _ := os.Stat(lock); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}

	// Idempotent.
	if code, _, stderr := runCLI(t, "--from-dir", fixtureDir, "--write-lock", lock); code != 0 {
		t.Fatalf("second run exit %d: %s", code, stderr)
	}
	again, _ := os.ReadFile(lock)
	if !bytes.Equal(again, got) {
		t.Fatal("second write changed the lock")
	}
}

func TestReplaceTopLevel(t *testing.T) {
	in := []byte(`{"b":1,"a":{"x":[1,2]},"n":12345678901234567}`)
	out, err := replaceTopLevel(in, "baseline_digests", map[string]string{"admission": "x"})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"b\": 1,\n  \"a\": {\n    \"x\": [\n      1,\n      2\n    ]\n  },\n  \"n\": 12345678901234567,\n  \"baseline_digests\": {\n    \"admission\": \"x\"\n  }\n}\n"
	if string(out) != want {
		t.Fatalf("got\n%s", out)
	}
	for _, bad := range []string{`[]`, `{"a":1,"a":2}`, `{"a":1} {}`, `{"a":`} {
		if _, err := replaceTopLevel([]byte(bad), "k", 1); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func copyFixtures(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ents, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(fixtureDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(dir string) error
		errSub string
	}{
		{"missing source file", func(dir string) error { return os.Remove(filepath.Join(dir, "networkloggings.json")) }, "networkloggings.json"},
		{"missing cluster", func(dir string) error { return os.Remove(filepath.Join(dir, "cluster.json")) }, "cluster.json"},
		{"named object absent", func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "tetragon-config.json"), []byte(`{"apiVersion":"v1","kind":"ConfigMapList","items":[]}`), 0o644)
		}, "ConfigMap agent-sensors/tetragon-config"},
		{"release policy absent", func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "tracingpoliciesnamespaced.json"), []byte(`{"items":[]}`), 0o644)
		}, "agent-exec/agentarium-tcp-connect"},
		{"invalid JSON", func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "roles.json"), []byte(`{"items":[`), 0o644)
		}, "roles.json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := copyFixtures(t)
			if err := c.mutate(dir); err != nil {
				t.Fatal(err)
			}
			lock := filepath.Join(t.TempDir(), "lock.json")
			orig, _ := os.ReadFile(exampleLock)
			os.WriteFile(lock, orig, 0o644)
			code, out, stderr := runCLI(t, "--from-dir", dir, "--write-lock", lock)
			if code == 0 || out != "" || !strings.Contains(stderr, c.errSub) {
				t.Fatalf("exit %d stdout %q stderr %q", code, out, stderr)
			}
			if after, _ := os.ReadFile(lock); !bytes.Equal(after, orig) {
				t.Fatal("lock changed on failure")
			}
		})
	}
}

func TestFlagRules(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "lock.json")
	os.WriteFile(lock, []byte(`{"environment":"prod","project":{"id":"p","location":"l"}}`), 0o644)
	for _, args := range [][]string{
		{},
		{"--lock", lock},   // no --context: never falls back to the current context
		{"--context", "c"}, // no --lock
		{"--from-dir", fixtureDir, "--context", "c"},       // conflicting modes
		{"--from-dir", fixtureDir, "--lock", lock},         // conflicting modes
		{"--from-dir", fixtureDir, "extra-positional-arg"}, // unexpected args
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestLiveRejectsUnknownContextAndPlaceholderLock(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	os.WriteFile(kc, []byte(`apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://127.0.0.1:1"}}]
users: [{name: u, user: {token: t}}]
contexts: [{name: other, context: {cluster: c, user: u}}]
current-context: other
`), 0o600)
	good := filepath.Join(dir, "lock.json")
	os.WriteFile(good, []byte(`{"environment":"prod","project":{"id":"p","location":"l"}}`), 0o644)
	code, _, stderr := runCLI(t, "--kubeconfig", kc, "--context", "missing", "--lock", good)
	if code != 1 || !strings.Contains(stderr, `context "missing" not found`) {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	code, _, stderr = runCLI(t, "--kubeconfig", kc, "--context", "other", "--lock", exampleLock)
	if code != 1 || !strings.Contains(stderr, "project.id is not set") && !strings.Contains(stderr, "project.location is not set") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}
