package netpolcollector

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	"github.com/google/uuid"
)

// Captured is an INTERNAL local spool format, not the pending batch wire.
// A future verified wire adapter can derive record_id from the immutable identity
// fields. This producer neither invents that namespace nor accepts server ACKs.
type Captured struct {
	CaptureVersion       int         `json:"capture_version"`
	ClusterUID           string      `json:"cluster_uid"`
	NodeUID              string      `json:"node_uid"`
	SourceEpoch          string      `json:"source_epoch"`
	SourceSequence       uint64      `json:"source_sequence"`
	NormalizationVersion string      `json:"normalization_version"`
	Observation          Observation `json:"observation"`
}
type Config struct {
	Journal                                             *wal.Journal
	Reader                                              Reader
	ClusterUID, NodeUID, NodeName, NormalizationVersion string
}
type Capture struct {
	mu     sync.Mutex
	config Config
}

func validUUID(s string) bool {
	u, e := uuid.Parse(s)
	return e == nil && u != uuid.Nil && u.String() == s
}
func New(c Config) (*Capture, error) {
	if c.Journal == nil || c.Reader.Inventory == nil || c.Reader.MaxFiles < 1 || c.Reader.MaxFiles > 64 || c.Reader.MaxLineBytes < 1 || c.Reader.MaxLineBytes > wal.MaxRecordBytes || !validUUID(c.ClusterUID) || !validUUID(c.NodeUID) || c.NodeName == "" || c.NormalizationVersion == "" || len(c.NormalizationVersion) > 128 {
		return nil, errors.New("invalid netpol capture configuration")
	}
	return &Capture{config: c}, nil
}

// Step exposes a record only after the shared WAL fsyncs both data and cursor.
// A schema-invalid complete line returns a zero record after its rejection
// count and cursor are durably committed together. Wrong-node metadata, disk
// errors or missing rotation history never advance the source cursor. A valid
// record that cannot fit in the WAL also leaves the cursor unchanged.
// Lease reporting remains deferred to the wire contract in issue #103.
func (c *Capture) Step(ctx context.Context) (wal.Record, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return wal.Record{}, e
	}
	checkpoint := c.config.Journal.Checkpoint()
	line, e := c.config.Reader.Next(checkpoint)
	if e != nil {
		return wal.Record{}, e
	}
	observed, e := Normalize(line.Bytes)
	if e != nil {
		if !errors.Is(e, ErrSchema) {
			return wal.Record{}, e
		}
		if e := ctx.Err(); e != nil {
			return wal.Record{}, e
		}
		return wal.Record{}, c.config.Journal.RejectSchema(checkpoint, line.Checkpoint)
	}
	if observed.NodeName != c.config.NodeName {
		return wal.Record{}, ErrSchema
	}
	if e := ctx.Err(); e != nil {
		return wal.Record{}, e
	}
	return c.config.Journal.Append(func(epoch string, sequence uint64) ([]byte, error) {
		return canonical.CanonicalJSON(Captured{1, c.config.ClusterUID, c.config.NodeUID, epoch, sequence, c.config.NormalizationVersion, observed})
	}, line.Checkpoint)
}

// Run is a bounded local capture loop. Follow polls incomplete live lines/EOF;
// it stops on errors without ACK/deletion, healthy leases, or final-flush claims.
func (c *Capture) Run(ctx context.Context, follow bool) error {
	for {
		_, e := c.Step(ctx)
		if !errors.Is(e, io.EOF) && !(follow && errors.Is(e, ErrInventoryChanged)) {
			if e != nil {
				return e
			}
			continue
		}
		if !follow {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
