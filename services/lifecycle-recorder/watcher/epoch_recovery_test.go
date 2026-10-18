package watcher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

func privateDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestInitialEpochTemporaryFilesRecover(t *testing.T) {
	for _, stage := range []string{"created", "partial-write", "synced-before-rename"} {
		t.Run(stage, func(t *testing.T) {
			dir := privateDirectory(t)
			raw := []byte{}
			if stage == "partial-write" {
				raw = []byte(`{"version":1,"instance":`)
			}
			abandoned := epochState{Version: 1, Instance: strings.Repeat("a", 32), Counter: 1, Scope: "namespace/agent-exec", ClusterUID: clusterUID}
			abandoned.Checksum = epochChecksum(abandoned)
			if stage == "synced-before-rename" {
				raw, _ = json.Marshal(abandoned)
			}
			pending, err := os.CreateTemp(dir, "epoch-pending-")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pending.Write(raw); err != nil {
				t.Fatal(err)
			}
			if err = pending.Sync(); err != nil {
				t.Fatal(err)
			}
			if err = pending.Close(); err != nil {
				t.Fatal(err)
			}
			if err = syncDirectory(dir); err != nil {
				t.Fatal(err)
			}
			lease, err := openEpoch(dir, "namespace/agent-exec", clusterUID)
			if err != nil {
				t.Fatalf("initial crash did not recover: %v", err)
			}
			first := lease.epoch
			if err = lease.close(); err != nil {
				t.Fatal(err)
			}
			if first == abandoned.Instance+"_1" || !strings.HasSuffix(first, "_1") {
				t.Fatalf("adopted uncommitted identity: %s", first)
			}
			if _, err = os.Lstat(pending.Name()); !os.IsNotExist(err) {
				t.Fatalf("orphan temp remains: %v", err)
			}
			next, err := openEpoch(dir, "namespace/agent-exec", clusterUID)
			if err != nil {
				t.Fatal(err)
			}
			defer next.close()
			if next.epoch != strings.TrimSuffix(first, "_1")+"_2" {
				t.Fatalf("restart counter lost: %s -> %s", first, next.epoch)
			}
		})
	}
}

func TestMissingIdentityWithPublishedStatePreservesEverything(t *testing.T) {
	for _, state := range []string{"initialized", "wal", "unknown-file"} {
		t.Run(state, func(t *testing.T) {
			dir := privateDirectory(t)
			raw := []byte("preserve-this-temporary-file")
			pending := filepath.Join(dir, "epoch-pending-orphan")
			if err := os.WriteFile(pending, raw, 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, state)
			if state == "wal" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, []byte("published"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if lease, err := openEpoch(dir, "namespace/agent-exec", clusterUID); err == nil {
				lease.close()
				t.Fatal("missing durable identity was reinitialized")
			}
			got, err := os.ReadFile(pending)
			if err != nil || string(got) != string(raw) {
				t.Fatalf("pending evidence changed: %q %v", got, err)
			}
			if _, err = os.Lstat(path); err != nil {
				t.Fatal(err)
			}
			if _, err = os.Lstat(filepath.Join(dir, "instance.json")); !os.IsNotExist(err) {
				t.Fatal("invented identity")
			}
		})
	}
}

func TestInitialEpochRejectsUnsafeTemporaryEntries(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "world-readable"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateDirectory(t)
			target := filepath.Join(privateDirectory(t), "target")
			if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "epoch-pending-unsafe")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, path)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "world-readable":
				err = os.WriteFile(path, []byte("untrusted"), 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			if lease, err := openEpoch(dir, "namespace/agent-exec", clusterUID); err == nil {
				lease.close()
				t.Fatal("unsafe temp accepted")
			}
			if _, err = os.Lstat(path); err != nil {
				t.Fatal("unsafe entry removed", err)
			}
			got, err := os.ReadFile(target)
			if err != nil || string(got) != "untouched" {
				t.Fatal("symlink target changed")
			}
		})
	}
}

func TestPrivateSpoolUnderFsGroupMount(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, os.ModeSetgid|0o775); err != nil {
		t.Fatal(err)
	}
	// fsGroup mount root is shared by group and cannot itself be the spool.
	if lease, err := openEpoch(root, "namespace/agent-exec", clusterUID); err == nil {
		lease.close()
		t.Fatal("shared mount root accepted as private spool")
	}
	dir := filepath.Join(root, "spool")
	for i := 0; i < 2; i++ {
		// OnRootMismatch preserves the already-correct mount root and leaves the
		// private child untouched on the next mount. Reopen epoch and actual WAL.
		lease, err := openEpoch(dir, "namespace/agent-exec", clusterUID)
		if err != nil {
			t.Fatal(err)
		}
		journal, err := wal.Open(filepath.Join(dir, "wal"), lease.epoch, 64<<20)
		if err != nil {
			lease.close()
			t.Fatal(err)
		}
		_, err = journal.Append(func(epoch string, seq uint64) ([]byte, error) {
			return json.Marshal(map[string]any{"source_epoch": epoch, "source_sequence": seq})
		}, wal.Checkpoint{Inode: 1, Offset: int64(i + 1)})
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		if err := lease.close(); err != nil {
			t.Fatal(err)
		}
		if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.Mode().Perm()&0o077 != 0 {
				t.Errorf("private spool permissions widened: %s %v", path, info.Mode())
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
