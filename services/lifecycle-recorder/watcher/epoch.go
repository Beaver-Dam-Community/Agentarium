package watcher

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

const maxCounter uint64 = 1<<53 - 1

var instancePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type epochState struct {
	Version    int    `json:"version"`
	Instance   string `json:"instance"`
	Counter    uint64 `json:"counter"`
	Scope      string `json:"scope"`
	ClusterUID string `json:"cluster_uid"`
	Checksum   string `json:"checksum,omitempty"`
}
type epochLease struct {
	file  *os.File
	epoch string
}

func (e *epochLease) close() error {
	_ = syscall.Flock(int(e.file.Fd()), syscall.LOCK_UN)
	return e.file.Close()
}
func syncDirectory(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func writeAtomic(dir, name string, raw []byte) error {
	f, e := os.CreateTemp(dir, "epoch-pending-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), filepath.Join(dir, name)); e != nil {
		return e
	}
	return syncDirectory(dir)
}

// openEpoch reserves and fsyncs a new process counter before opening its WAL.
// The identity lock remains held for the entire producer lifetime.
func openEpoch(dir, scope, clusterUID string) (lease *epochLease, err error) {
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("watcher directory must be owner-only")
	}
	fd, err := syscall.Open(filepath.Join(dir, "instance.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "instance.lock")
	lockInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, errors.New("invalid identity lock file")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("watcher identity is already in use")
	}
	lease = &epochLease{file: file}
	held := lease
	defer func() {
		if err != nil {
			_ = held.close()
		}
	}()
	state := epochState{Version: 1, Scope: scope, ClusterUID: clusterUID}
	path := filepath.Join(dir, "instance.json")
	f, openErr := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if openErr == nil {
		info, e := f.Stat()
		if e != nil {
			f.Close()
			return nil, e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 32768 {
			f.Close()
			return nil, errors.New("invalid watcher identity file")
		}
		raw, e := io.ReadAll(io.LimitReader(f, 32769))
		f.Close()
		if e != nil {
			return nil, e
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if canonical.CheckStrictJSON(raw) != nil || d.Decode(&state) != nil || d.Decode(new(any)) != io.EOF || state.Version != 1 || !instancePattern.MatchString(state.Instance) || state.Scope != scope || state.ClusterUID != clusterUID || state.Counter == 0 || state.Counter >= maxCounter || state.Checksum != epochChecksum(state) {
			return nil, errors.New("watcher identity corrupt, changed or exhausted")
		}
	} else if os.IsNotExist(openErr) {
		entries, e := os.ReadDir(dir)
		if e != nil {
			return nil, e
		}
		// Open cannot create a WAL or publish an epoch until both instance.json
		// and the initialized marker have been synced. A directory containing
		// only this lock and abandoned atomic-write temporaries therefore has
		// no published identity to recover. Never adopt a partially written
		// temporary identity or remove anything once initialized/WAL state exists.
		pending := []string{}
		for _, entry := range entries {
			if entry.Name() == "instance.lock" {
				continue
			}
			info, e := entry.Info()
			if e != nil {
				return nil, e
			}
			if !strings.HasPrefix(entry.Name(), "epoch-pending-") || entry.Name() == "epoch-pending-" || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return nil, errors.New("missing durable watcher identity; preserve existing state")
			}
			pending = append(pending, filepath.Join(dir, entry.Name()))
		}
		// Validate the entire directory before deleting any temporary evidence.
		// The lifetime lock and owner-only directory still apply during cleanup.
		for _, path := range pending {
			if e := os.Remove(path); e != nil {
				return nil, e
			}
		}
		if len(pending) > 0 {
			if e := syncDirectory(dir); e != nil {
				return nil, e
			}
		}
		id, e := uuid.NewRandom()
		if e != nil {
			return nil, e
		}
		state.Instance = strings.ReplaceAll(id.String(), "-", "")
	} else {
		return nil, openErr
	}
	state.Counter++
	state.Checksum = epochChecksum(state)
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	if err = writeAtomic(dir, "instance.json", raw); err != nil {
		return nil, err
	}
	marker, err := os.OpenFile(filepath.Join(dir, "initialized"), os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	err = marker.Sync()
	ce := marker.Close()
	if err == nil {
		err = ce
	}
	if err == nil {
		err = syncDirectory(dir)
	}
	if err != nil {
		return nil, err
	}
	lease.epoch = fmt.Sprintf("%s_%d", state.Instance, state.Counter)
	return lease, nil
}

func epochChecksum(state epochState) string {
	state.Checksum = ""
	raw, _ := json.Marshal(state)
	return canonical.SHA256Hex(raw)
}
