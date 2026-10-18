package wal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// This is local recovery evidence, never an event or a wire reason enum. The
// frame contains bounded JSON metadata followed by the exact damaged bytes.
// Hashing the metadata also binds the filename to the position and cause.
type damage struct {
	Version  int    `json:"version"`
	Epoch    string `json:"epoch"`
	First    uint64 `json:"segment_first"`
	Sequence uint64 `json:"sequence"`
	Offset   int64  `json:"offset"`
	Reason   string `json:"reason"`
	Bytes    int64  `json:"bytes"`
	Digest   string `json:"sha256"`
}

const damageLimit = MaxRecordBytes + 12 + 4096 + 8

func damageName(metadata []byte) string {
	return "damaged-" + canonical.SHA256Hex(metadata) + ".bin"
}

func readDamage(path string) ([]byte, damage, error) {
	var d damage
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, d, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, d, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > damageLimit {
		return nil, d, errors.New("invalid damaged-tail evidence file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, damageLimit+1))
	if err != nil {
		return nil, d, err
	}
	if len(raw) < 8 || len(raw) > damageLimit || string(raw[:4]) != "AGQ1" {
		return nil, d, errors.New("invalid damaged-tail evidence frame")
	}
	n := int(binary.BigEndian.Uint32(raw[4:8]))
	if n < 1 || n > 4096 || 8+n >= len(raw) {
		return nil, d, errors.New("invalid damaged-tail metadata length")
	}
	meta, tail := raw[8:8+n], raw[8+n:]
	decoder := json.NewDecoder(bytes.NewReader(meta))
	decoder.DisallowUnknownFields()
	if canonical.CheckStrictJSON(meta) != nil || decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, d, errors.New("invalid damaged-tail metadata")
	}
	if d.Version != 1 || !epochPattern.MatchString(d.Epoch) || d.First < 1 || d.Sequence < d.First || d.Sequence > MaxSequence || d.Offset < 0 || d.Offset > MaxSegmentBytes || d.Bytes < 1 || d.Bytes > MaxRecordBytes+12 || d.Offset+d.Bytes > MaxSegmentBytes || d.Bytes != int64(len(tail)) || d.Digest != canonical.SHA256Hex(tail) || filepath.Base(path) != damageName(meta) {
		return nil, d, errors.New("damaged-tail evidence identity or digest mismatch")
	}
	if d.Reason != "partial_header" && d.Reason != "partial_payload" && d.Reason != "crc_mismatch" {
		return nil, d, errors.New("invalid damaged-tail cause")
	}
	return raw, d, nil
}

func (j *Journal) loadDamage() error {
	paths, err := filepath.Glob(filepath.Join(j.dir, "damaged-*.bin"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		raw, d, err := readDamage(path)
		if err != nil {
			return err
		}
		p, ok := j.state.Epochs[d.Epoch]
		if !ok || d.Sequence > p.Reserved {
			return errors.New("unreserved damaged-tail evidence")
		}
		j.used += int64(len(raw))
	}
	// A crash can leave an unpublished temporary copy. Retain and account for
	// it; it is not evidence permitting truncation or an acknowledgement.
	paths, err = filepath.Glob(filepath.Join(j.dir, "damage-pending-*"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > damageLimit {
			return errors.New("invalid pending damage file")
		}
		j.used += info.Size()
	}
	return nil
}

func (j *Journal) preserveDamage(f *os.File, epoch string, first, sequence uint64, offset, total int64, reason string) error {
	if total <= offset || total-offset > MaxRecordBytes+12 || total > MaxSegmentBytes || sequence > j.state.Epochs[epoch].Reserved {
		return ErrCorrupt
	}
	tail := make([]byte, total-offset)
	if _, err := f.ReadAt(tail, offset); err != nil {
		return err
	}
	d := damage{1, epoch, first, sequence, offset, reason, int64(len(tail)), canonical.SHA256Hex(tail)}
	meta, err := canonical.CanonicalJSON(d)
	if err != nil {
		return err
	}
	raw := make([]byte, 8, 8+len(meta)+len(tail))
	copy(raw, "AGQ1")
	binary.BigEndian.PutUint32(raw[4:8], uint32(len(meta)))
	raw = append(raw, meta...)
	raw = append(raw, tail...)
	path := filepath.Join(j.dir, damageName(meta))
	if previous, _, err := readDamage(path); err == nil {
		if !bytes.Equal(previous, raw) {
			return ErrCorrupt
		}
		// It may have been published immediately before a process crash.
		return syncDir(j.dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if int64(len(raw)) > j.capacity-j.used {
		return ErrFull
	}
	tmp, err := os.CreateTemp(j.dir, "damage-pending-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(raw); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	// Link publishes without overwriting any existing evidence. A conflicting
	// path stops recovery, even if a caller ignored the exclusive spool lock.
	if err == nil {
		err = os.Link(tmp.Name(), path)
	}
	if err == nil {
		err = syncDir(j.dir)
	}
	if err != nil {
		return err
	}
	j.used += int64(len(raw))
	return nil
}
