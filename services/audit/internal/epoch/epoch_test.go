package epoch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMonotonicExclusiveAndNoReset(t *testing.T) {
	dir := t.TempDir()
	first, release, err := Acquire(dir)
	if err != nil || !strings.HasSuffix(first, "_1") || len(first) != 34 {
		t.Fatalf("%s %v", first, err)
	}
	if _, _, err := Acquire(dir); err == nil {
		t.Fatal("concurrent producer accepted")
	}
	release()
	next, release, err := Acquire(dir)
	if err != nil || next != strings.TrimSuffix(first, "_1")+"_2" {
		t.Fatalf("%s %v", next, err)
	}
	release()
	if err := os.Remove(filepath.Join(dir, "counter")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Acquire(dir); err == nil {
		t.Fatal("lost epoch reset")
	}
}
func TestCorruptEpochFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "counter"), []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Acquire(dir); err == nil {
		t.Fatal("corrupt epoch reset")
	}
}

func TestMissingInstanceFailsClosed(t *testing.T) {
	dir := t.TempDir()
	_, release, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err := os.Remove(filepath.Join(dir, "instance")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Acquire(dir); err == nil {
		t.Fatal("lost instance reset")
	}
}
