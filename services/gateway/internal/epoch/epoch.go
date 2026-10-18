// Package epoch allocates monotonic producer epochs on a persistent volume.
//
// Copy of services/control-health/internal/epoch (Go internal packages cannot
// be shared across services), as in services/identity/internal/epoch and
// services/coordinator/internal/epoch. The gateway's AuditEvent source_epoch
// is a durable restart counter (COMMON AuditEvent); consolidate the copies
// later.
package epoch

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Acquire holds an OS advisory lock until release. Both the counter rename and
// its parent directory are fsynced before the epoch is exposed to a producer.
// A missing counter on an existing lock directory is not silently reset.
func Acquire(dir string) (value string, release func(), err error) {
	if dir == "" {
		return "", nil, errors.New("persistent epoch directory required")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return
	}
	lock, e := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return "", nil, e
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		lock.Close()
		return "", nil, errors.New("producer epoch already in use")
	}
	release = func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	raw, e := os.ReadFile(filepath.Join(dir, "counter"))
	n := uint64(0)
	if e == nil {
		n, e = strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 53)
		if e != nil || n == 0 {
			return "", release, errors.New("corrupt epoch counter")
		}
	} else if !os.IsNotExist(e) {
		return "", release, e
	}
	// The initialized marker prevents reset after deletion of an existing counter.
	if os.IsNotExist(e) {
		if _, markerErr := os.Stat(filepath.Join(dir, "initialized")); markerErr == nil {
			return "", release, errors.New("epoch counter missing")
		} else if !os.IsNotExist(markerErr) {
			return "", release, markerErr
		}
	}
	if n >= 9007199254740991 {
		return "", release, errors.New("epoch exhausted")
	}
	n++
	tmp, e := os.CreateTemp(dir, "counter-")
	if e != nil {
		return "", release, e
	}
	defer os.Remove(tmp.Name())
	value = strconv.FormatUint(n, 10)
	if _, e = tmp.WriteString(value + "\n"); e == nil {
		e = tmp.Sync()
	}
	closeErr := tmp.Close()
	if e != nil {
		return "", release, e
	}
	if closeErr != nil {
		return "", release, closeErr
	}
	if e = os.Rename(tmp.Name(), filepath.Join(dir, "counter")); e != nil {
		return "", release, e
	}
	marker, e := os.OpenFile(filepath.Join(dir, "initialized"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return "", release, e
	}
	e = marker.Sync()
	_ = marker.Close()
	if e != nil {
		return "", release, e
	}
	parent, e := os.Open(dir)
	if e != nil {
		return "", release, e
	}
	e = parent.Sync()
	_ = parent.Close()
	if e != nil {
		return "", release, e
	}
	success = true
	return value, release, nil
}
