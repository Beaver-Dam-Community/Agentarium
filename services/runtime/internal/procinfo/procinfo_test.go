package procinfo

import "testing"

func TestStartTicks(t *testing.T) {
	// A real /proc/<pid>/stat line with a comm containing spaces and ')'.
	line := "4242 (a) b (c)) S 1 4242 4242 0 -1 4194560 120 0 0 0 1 0 0 0 20 0 1 0 987654 1234567 89 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n"
	got, err := StartTicks([]byte(line))
	if err != nil || got != 987654 {
		t.Fatalf("StartTicks = %d, %v; want 987654", got, err)
	}
	for _, bad := range []string{"", "1 (x S 1", "1 (x) S 1 2 3", "1 (x) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 zero 1"} {
		if _, err := StartTicks([]byte(bad)); err == nil {
			t.Errorf("StartTicks(%q) accepted", bad)
		}
	}
}

func TestHintValid(t *testing.T) {
	if (Hint{LocalPID: 1, PIDNSInode: 1}).Valid() {
		t.Fatal("hint without start ticks is valid")
	}
	if !(Hint{LocalPID: 1, PIDNSInode: 2, StartTicks: 3}).Valid() {
		t.Fatal("complete hint is invalid")
	}
}
