package observe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestHostProcReadsNodeProcfsAndCgroup(t *testing.T) {
	root, cgroups := t.TempDir(), t.TempDir()
	id := strings.Repeat("c", 64)
	pid := filepath.Join(root, "9001")
	if err := os.MkdirAll(pid, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(pid, name), []byte(body), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	write("status", "Name:\tpython3\nPPid:\t9000\nUid:\t10001\t10001\t10001\t10001\nNSpid:\t9001\t7\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n")
	// comm with spaces and parentheses; starttime is field 22.
	write("stat", "9001 (py (x) 3) S 9000 9001 9001 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 123456 1000 10 18446744073709551615\n")
	write("cgroup", "0::/../../kubepods.slice/cri-containerd-"+id+".scope\n")
	dir := filepath.Join(cgroups, "kubepods.slice", "kubepods-burstable.slice", "kubepods-burstable-podx.slice", "cri-containerd-"+id+".scope")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := HostProc{Root: root, CgroupRoot: cgroups}
	pids, err := p.PIDs()
	if err != nil || len(pids) != 1 || pids[0] != 9001 {
		t.Fatalf("pids %v %v", pids, err)
	}
	s, err := p.Status(9001)
	if err != nil || s.PPid != 9000 || len(s.NSpid) != 2 || s.NSpid[1] != 7 || *s.NoNewPrivs != 1 || *s.Seccomp != 2 || *s.CapEff != "0000000000000000" || s.UID[1] != 10001 {
		t.Fatalf("status %+v %v", s, err)
	}
	if ticks, err := p.StartTicks(9001); err != nil || ticks != 123456 {
		t.Fatalf("ticks %d %v", ticks, err)
	}
	if cg, err := p.Cgroup(9001); err != nil || !strings.HasSuffix(cg, id+".scope") {
		t.Fatalf("cgroup %q %v", cg, err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	if inode, err := p.CgroupInode(id); err != nil || inode != int64(st.Ino) {
		t.Fatalf("inode %d %v", inode, err)
	}
	// A second directory for the same ID is ambiguous; a missing one unknown.
	if err := os.MkdirAll(filepath.Join(cgroups, "other", "cri-containerd-"+id+".scope"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CgroupInode(id); err == nil {
		t.Fatal("ambiguous container cgroup resolved")
	}
	if _, err := p.CgroupInode(strings.Repeat("d", 64)); err == nil {
		t.Fatal("missing container cgroup resolved")
	}
	if _, err := p.Status(9002); err == nil {
		t.Fatal("missing process has a status")
	}
	if _, err := parseStatus([]byte("Name:\tx\nPPid:\t1\n")); err == nil {
		t.Fatal("status without NSpid accepted")
	}
}

func TestIndexKeepsOnlyCommittedExecLineage(t *testing.T) {
	x := NewIndex(nil)
	exec := func(id string, pid int64) []byte {
		raw, _ := json.Marshal(map[string]any{"event_type": "process_exec", "source_event_id": "ref-" + id, "process_exec_id": id, "host_pid": pid, "container_id": "c"})
		return raw
	}
	exit, _ := json.Marshal(map[string]any{"event_type": "process_exit", "process_exec_id": "b"})
	x.Namespace("a", 7)
	x.Committed(exec("a", 10))
	x.Committed(exit) // exit committed before its exec in another batch
	x.Committed(exec("b", 10))
	x.Committed(exec("a", 10)) // replayed record is not a second exec
	x.Committed([]byte(`{"event_type":"tcp_connect","process_exec_id":"z","host_pid":10,"container_id":"c"}`))
	got := x.ByPID("c", 10)
	if len(got) != 2 || got[0].ExecID != "a" || got[0].PIDNS != 7 || got[0].Exited || !got[1].Exited || got[0].SourceEventID != "ref-a" {
		t.Fatalf("index %+v", got)
	}
	if !x.HasContainer("c") || x.HasContainer("d") {
		t.Fatal("container presence")
	}
}
