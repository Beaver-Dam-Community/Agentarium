package probe

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMarkerStimulus(t *testing.T) {
	ok, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	if err := Marker(ok)(context.Background()); err != nil {
		t.Fatal(err)
	}
	bad, err := exec.LookPath("false")
	if err != nil {
		t.Fatal(err)
	}
	if err := Marker(bad)(context.Background()); err == nil {
		t.Fatal("non-zero exit accepted")
	}
	if err := Marker(filepath.Join(t.TempDir(), "missing"))(context.Background()); err == nil {
		t.Fatal("missing marker accepted")
	}
}

func TestConnectStimulus(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			// The runner closes its side: the sink reads EOF.
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_, err = c.Read(make([]byte, 1))
			c.Close()
		}
		accepted <- err
	}()
	if err := Connect(l.Addr().String())(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err == nil || !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("sink saw %v, want EOF from the runner's close", err)
	}
	addr := l.Addr().String()
	l.Close()
	if err := Connect(addr)(context.Background()); err == nil {
		t.Fatal("refused connect accepted")
	}
}

func TestFixtureStimulus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected-fixture")
	err := Fixture(path)(context.Background())
	if os.Geteuid() == 0 {
		// root has CAP_DAC_OVERRIDE: the denied open would succeed, so the
		// stimulus must not claim it ran as intended.
		if err == nil || !strings.Contains(err.Error(), "DAC override") {
			t.Fatalf("root run: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	// The fixture is left unreadable; the next cycle reopens it.
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0 {
		t.Fatalf("fixture mode %v %v", fi, err)
	}
	if err := Fixture(path)(context.Background()); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if err := Fixture(filepath.Join(t.TempDir(), "missing-dir", "f"))(context.Background()); err == nil {
		t.Fatal("unwritable fixture accepted")
	}
}
