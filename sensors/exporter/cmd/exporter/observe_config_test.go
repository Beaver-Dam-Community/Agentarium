package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The node observation keys are all-or-nothing; without them the exporter
// runs and the responder stays off (challenges time out, nothing is vouched).
func TestNodeObservationConfigAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	base := Config{Version: "v", ExportFile: "/e", SpoolDir: "/s", BootIDPath: "/b", TokenFile: "/t", CAFile: "/c", TetragonConfigDir: "/d",
		CollectorOrigin: "https://c", HealthOrigin: "https://h", IdentityOrigin: "https://i", RecoveryReason: "r", MetadataGraceSeconds: 1, PodRetentionSeconds: 1}
	load := func(c Config) (Config, error) {
		raw, _ := json.Marshal(c)
		p := filepath.Join(dir, "config.json")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return loadConfig(p)
	}
	if c, err := load(base); err != nil || c.observes() {
		t.Fatalf("config without observation keys: %v", err)
	}
	full := base
	full.ProcRoot, full.CgroupRoot, full.WorkerBinaries = "/host/proc", "/host/sys/fs/cgroup", []string{"/usr/local/bin/python3"}
	if c, err := load(full); err != nil || !c.observes() {
		t.Fatalf("full observation config: %v", err)
	}
	for name, c := range map[string]Config{
		"no cgroup":   func() Config { c := full; c.CgroupRoot = ""; return c }(),
		"no binaries": func() Config { c := full; c.WorkerBinaries = nil; return c }(),
		"no proc":     func() Config { c := full; c.ProcRoot = ""; return c }(),
		"relative":    func() Config { c := full; c.WorkerBinaries = []string{"python3"}; return c }(),
	} {
		if _, err := load(c); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
