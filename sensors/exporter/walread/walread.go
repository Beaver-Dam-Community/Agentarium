// Package walread is a read-only view of AGW1 segments for operators and the
// live verification harness. It never takes the journal lock, repairs, acks or
// deletes anything. A segment may be appended or removed concurrently, so a
// partial final frame ends that segment and a vanished segment is skipped.
package walread

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const maxRecord = 1 << 20

var crcTable = crc32.MakeTable(crc32.Castagnoli)
var ErrCorrupt = errors.New("corrupt WAL frame before segment end")

// Each calls fn with every complete, CRC-valid payload in segment-name order.
// Payload bytes are the exact JCS KernelEvent written by the exporter.
func Each(dir string, fn func(segment string, payload []byte) error) error {
	files, err := filepath.Glob(filepath.Join(dir, "wal-*.seg"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, path := range files {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		err = frames(f, func(p []byte) error { return fn(filepath.Base(path), p) })
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func frames(r io.Reader, fn func([]byte) error) error {
	header := make([]byte, 12)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		length := binary.BigEndian.Uint32(header[4:8])
		if string(header[:4]) != "AGW1" || length == 0 || length > maxRecord {
			return ErrCorrupt
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		if crc32.Checksum(payload, crcTable) != binary.BigEndian.Uint32(header[8:12]) {
			// A torn final frame is the writer's in-progress append.
			if _, err := r.Read(make([]byte, 1)); errors.Is(err, io.EOF) {
				return nil
			}
			return ErrCorrupt
		}
		if err := fn(payload); err != nil {
			return err
		}
	}
}
