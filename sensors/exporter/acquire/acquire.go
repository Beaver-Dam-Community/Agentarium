// Package acquire connects a stable Tetragon rotation inventory to the fsynced
// WAL boundary. It leaves the event wire contract and policy filter to the
// normalizer adapter, which must not invent observation metadata.
package acquire

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/tailer"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

// Prepared separates successful policy exclusion from parsing, metadata, or
// normalization failures. Exactly one of Excluded and Build must be supplied.
// Build is called before sequence reservation and must return a normalized,
// privacy-filtered record using exactly the provided epoch/sequence.
type Prepared struct {
	Excluded bool
	Build    func(epoch string, sequence uint64) ([]byte, error)
}
type Normalize func(context.Context, []byte) (Prepared, error)

type Config struct {
	Journal                *wal.Journal
	LiveFile               string
	MaxFiles, MaxLineBytes int
	Normalize              Normalize
}

type Collector struct {
	mu     sync.Mutex
	config Config
}

func New(c Config) (*Collector, error) {
	if c.Journal == nil || c.Normalize == nil || !filepath.IsAbs(c.LiveFile) || filepath.Clean(c.LiveFile) != c.LiveFile || c.MaxFiles < 1 || c.MaxFiles > 1024 || c.MaxLineBytes < 1 || c.MaxLineBytes > wal.MaxRecordBytes {
		return nil, errors.New("invalid acquisition configuration")
	}
	return &Collector{config: c}, nil
}

type Result struct {
	Idle, Filtered bool
	// Record is set only after frame and input checkpoint are durable.
	Record *wal.Record
}

type StageError struct {
	Stage string
	Cause error
}

// Do not include upstream event bytes or a normalizer's error text in logs.
func (e *StageError) Error() string { return "export acquisition failed at " + e.Stage }
func (e *StageError) Unwrap() error { return e.Cause }

// Step consumes at most one complete input line. There is one collector per
// journal. A preparation error, metadata-pending result, invalid adapter result,
// or WAL failure never advances the input checkpoint as a policy exclusion.
func (c *Collector) Step(ctx context.Context) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	line, err := tailer.NextFile(c.config.LiveFile, c.config.Journal.Checkpoint(), c.config.MaxLineBytes, c.config.MaxFiles)
	if errors.Is(err, io.EOF) {
		return Result{Idle: true}, nil
	}
	if err != nil {
		return Result{}, &StageError{"read", err}
	}
	prepared, err := c.config.Normalize(ctx, line.Bytes)
	if err != nil {
		return Result{}, &StageError{"normalize", err}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if prepared.Excluded == (prepared.Build != nil) {
		return Result{}, &StageError{"normalize", errors.New("normalizer must return exactly one of exclusion or record builder")}
	}
	if prepared.Excluded {
		if err := c.config.Journal.AdvanceFiltered(line.Checkpoint); err != nil {
			return Result{}, &StageError{"checkpoint", err}
		}
		return Result{Filtered: true}, nil
	}
	record, err := c.config.Journal.Append(prepared.Build, line.Checkpoint)
	if err != nil {
		return Result{}, &StageError{"wal", err}
	}
	return Result{Record: &record}, nil
}

// Run polls an idle/rotating file at 100 ms and consumes available complete lines
// immediately. Actual rotation loss and normalization/durability errors return
// to the supervisor for gap/lease/hold reporting; they are never skipped. It does
// not assert readiness or manipulate upstream Tetragon capture.
func (c *Collector) Run(ctx context.Context) error {
	for {
		result, err := c.Step(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil && !errors.Is(err, tailer.ErrInventoryChanged) {
			return err
		}
		if result.Idle || err != nil {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
}
