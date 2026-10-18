package observe

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Status is the subset of /proc/<pid>/status the witness reads. Pointers are
// nil when the kernel did not print the field (unknown, not zero).
type Status struct {
	NSpid      []int64
	PPid       int64
	UID        []int64 // real, effective, saved, filesystem
	NoNewPrivs *int64
	Seccomp    *int64
	CapEff     *string
}

// Proc is the node process source. The production implementation reads the
// host procfs and cgroup2 mounts; tests use a fake.
type Proc interface {
	PIDs() ([]int64, error)
	Status(pid int64) (Status, error)
	// StartTicks is field 22 of /proc/<pid>/stat (clock ticks since boot).
	StartTicks(pid int64) (int64, error)
	// Cgroup is the unified ("0::") cgroup path of /proc/<pid>/cgroup.
	Cgroup(pid int64) (string, error)
	// CgroupInode is the inode of the one cgroup2 directory named for the
	// full container ID.
	CgroupInode(containerID string) (int64, error)
}

// HostProc reads a host procfs mounted at Root and the host cgroup2
// hierarchy mounted at CgroupRoot. Only world-readable files are read;
// /proc/<pid>/ns needs ptrace access the exporter does not have, so the PID
// namespace inode comes from Tetragon instead (Index.Namespace).
type HostProc struct{ Root, CgroupRoot string }

var ErrUnavailable = errors.New("process state unavailable")

func (p HostProc) path(pid int64, name string) string {
	return filepath.Join(p.Root, strconv.FormatInt(pid, 10), name)
}

func (p HostProc) PIDs() ([]int64, error) {
	entries, err := os.ReadDir(p.Root)
	if err != nil {
		return nil, ErrUnavailable
	}
	var out []int64
	for _, e := range entries {
		if n, err := strconv.ParseInt(e.Name(), 10, 64); err == nil && n > 0 && e.IsDir() {
			out = append(out, n)
		}
	}
	return out, nil
}

func ints(fields []string) ([]int64, bool) {
	out := make([]int64, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.ParseInt(f, 10, 64)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

func (p HostProc) Status(pid int64) (Status, error) {
	raw, err := os.ReadFile(p.path(pid, "status"))
	if err != nil {
		return Status{}, ErrUnavailable
	}
	return parseStatus(raw)
}

func parseStatus(raw []byte) (Status, error) {
	var s Status
	ppid := false
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		switch key {
		case "NSpid":
			v, ok := ints(fields)
			if !ok {
				return Status{}, ErrUnavailable
			}
			s.NSpid = v
		case "PPid":
			v, ok := ints(fields)
			if !ok || len(v) != 1 {
				return Status{}, ErrUnavailable
			}
			s.PPid, ppid = v[0], true
		case "Uid":
			v, ok := ints(fields)
			if !ok || len(v) != 4 {
				return Status{}, ErrUnavailable
			}
			s.UID = v
		case "NoNewPrivs", "Seccomp":
			v, ok := ints(fields)
			if !ok || len(v) != 1 {
				return Status{}, ErrUnavailable
			}
			if key == "NoNewPrivs" {
				s.NoNewPrivs = &v[0]
			} else {
				s.Seccomp = &v[0]
			}
		case "CapEff":
			if len(fields) == 1 {
				c := fields[0]
				s.CapEff = &c
			}
		}
	}
	if len(s.NSpid) == 0 || !ppid {
		return Status{}, ErrUnavailable
	}
	return s, nil
}

func (p HostProc) StartTicks(pid int64) (int64, error) {
	raw, err := os.ReadFile(p.path(pid, "stat"))
	if err != nil {
		return 0, ErrUnavailable
	}
	return parseStartTicks(raw)
}

func parseStartTicks(raw []byte) (int64, error) {
	// comm (field 2) may contain spaces and parentheses; fields after the last
	// ')' start at field 3 (state). starttime is field 22.
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return 0, ErrUnavailable
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return 0, ErrUnavailable
	}
	n, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil || n <= 0 {
		return 0, ErrUnavailable
	}
	return n, nil
}

func (p HostProc) Cgroup(pid int64) (string, error) {
	raw, err := os.ReadFile(p.path(pid, "cgroup"))
	if err != nil {
		return "", ErrUnavailable
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok && path != "" {
			return path, nil
		}
	}
	return "", ErrUnavailable
}

// CgroupInode walks at most six levels of the cgroup2 hierarchy (GKE:
// kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<uid>.slice/
// cri-containerd-<id>.scope) for exactly one directory whose name contains the
// full container ID. The exporter's own cgroup namespace makes the
// /proc/<pid>/cgroup path relative, so it is not joined to the root directly.
func (p HostProc) CgroupInode(containerID string) (int64, error) {
	if len(containerID) != 64 || strings.Trim(containerID, "0123456789abcdef") != "" {
		return 0, ErrUnavailable
	}
	root := filepath.Clean(p.CgroupRoot)
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if rel != "." && strings.Count(rel, string(filepath.Separator)) >= 6 {
			return fs.SkipDir
		}
		if strings.Contains(d.Name(), containerID) {
			found = append(found, path)
			return fs.SkipDir
		}
		return nil
	})
	if err != nil || len(found) != 1 {
		return 0, ErrUnavailable
	}
	var st syscall.Stat_t
	if syscall.Stat(found[0], &st) != nil {
		return 0, ErrUnavailable
	}
	return int64(st.Ino), nil
}
