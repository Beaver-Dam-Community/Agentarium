// Package tailer resumes Tetragon JSON exports by inode and byte offset.
// Paths must be a rotation inventory ordered from oldest backup to live file.
// Nothing is acknowledged here: callers commit the returned cursor only after
// WAL fsync, or after a successful policy filter that allocates no sequence.
package tailer

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

var ErrRotationLoss = errors.New("EXPORT_ROTATION_LOSS: checkpoint inode missing")
var ErrTruncated = errors.New("export file truncated before checkpoint")
var ErrRecordTooLarge = errors.New("export record exceeds input limit")
var ErrIncompleteRotatedRecord = errors.New("rotated export ends in an incomplete record")

type Line struct {
	Bytes      []byte
	Checkpoint wal.Checkpoint
}

// Next returns io.EOF when no complete line is available. A partial live-file
// line remains unconsumed, so a later call can read its completed bytes. Missing
// checkpoint inodes and truncated files are explicit loss, never cursor resets.
func Next(paths []string, checkpoint wal.Checkpoint, maxBytes int) (Line, error) {
	if maxBytes < 1 || maxBytes > wal.MaxRecordBytes || checkpoint.Offset < 0 {
		return Line{}, errors.New("invalid tailer input")
	}
	if checkpoint.Inode == 0 && checkpoint.Offset != 0 {
		return Line{}, errors.New("offset without inode")
	}
	if checkpoint.Inode != 0 && (checkpoint.Device == 0 || len(checkpoint.PrefixDigest) != 64) {
		return Line{}, ErrRotationLoss
	}
	found := checkpoint.Inode == 0
	for i, path := range paths {
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return Line{}, err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return Line{}, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() {
			f.Close()
			return Line{}, fmt.Errorf("not a regular export file: %s", path)
		}
		inode := uint64(stat.Ino)
		if !found && (inode != checkpoint.Inode || uint64(stat.Dev) != checkpoint.Device) {
			f.Close()
			continue
		}
		offset := int64(0)
		if inode == checkpoint.Inode && uint64(stat.Dev) == checkpoint.Device {
			offset = checkpoint.Offset
		}
		found = true
		if offset > info.Size() {
			f.Close()
			return Line{}, ErrTruncated
		}
		// Hash a complete first line so appends do not alter the fingerprint.
		// The descriptor is pinned; reuse of a checkpoint inode with different
		// contents fails before seeking to a stale offset.
		prefix, prefixErr := bufio.NewReaderSize(f, maxBytes+1).ReadSlice('\n')
		if len(prefix) > maxBytes || errors.Is(prefixErr, bufio.ErrBufferFull) {
			f.Close()
			return Line{}, ErrRecordTooLarge
		}
		if prefixErr != nil && !errors.Is(prefixErr, io.EOF) {
			f.Close()
			return Line{}, prefixErr
		}
		sum := sha256.Sum256(prefix)
		fingerprint := hex.EncodeToString(sum[:])
		if inode == checkpoint.Inode && uint64(stat.Dev) == checkpoint.Device && fingerprint != checkpoint.PrefixDigest {
			f.Close()
			return Line{}, ErrRotationLoss
		}
		if _, err = f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return Line{}, err
		}
		reader := bufio.NewReaderSize(f, maxBytes+1)
		raw, readErr := reader.ReadSlice('\n')
		// ReadSlice aliases reader storage; own the returned bytes before closing.
		data := append([]byte(nil), raw...)
		closeErr := f.Close()
		if len(data) > maxBytes || errors.Is(readErr, bufio.ErrBufferFull) {
			return Line{}, ErrRecordTooLarge
		}
		if readErr == nil {
			if closeErr != nil {
				return Line{}, closeErr
			}
			return Line{data, wal.Checkpoint{Inode: inode, Offset: offset + int64(len(data)), Device: uint64(stat.Dev), PrefixDigest: fingerprint}}, nil
		}
		if !errors.Is(readErr, io.EOF) {
			return Line{}, readErr
		}
		if closeErr != nil {
			return Line{}, closeErr
		}
		if len(data) > 0 {
			if i < len(paths)-1 {
				return Line{}, ErrIncompleteRotatedRecord
			}
			return Line{}, io.EOF
		}
	}
	if !found {
		return Line{}, ErrRotationLoss
	}
	return Line{}, io.EOF
}
