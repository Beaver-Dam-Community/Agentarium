package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// ProbeObjects is the create-only, generation-pinned object surface the probe
// shares with batch export.
type ProbeObjects interface {
	CreateFixed(context.Context, string, string, []byte) (int64, error)
	Read(context.Context, string, int64) ([]byte, error)
}

// ExportProber performs the TASK-07 export probe: a create-only test object
// under probes/<yyyy-mm-dd>/<probe_id>.json, read back at the same generation
// and compared byte for byte. The object stays under bucket retention.
type ExportProber struct {
	Objects ProbeObjects
	Bucket  string
	// Timeout bounds one probe so its result can still be reported within the
	// health report window. The default is two seconds.
	Timeout time.Duration
}

// Probe returns outcome pass with a gs:// evidence ref, or fail with none.
func (p *ExportProber) Probe(ctx context.Context) (string, []string) {
	if p == nil || p.Objects == nil || p.Bucket == "" {
		return "fail", []string{}
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	id := uuid.NewString()
	now := time.Now().UTC()
	key := "probes/" + now.Format("2006-01-02") + "/" + id + ".json"
	body, err := json.Marshal(map[string]string{"probe_id": id, "created_at": now.Format(time.RFC3339Nano)})
	if err != nil {
		return "fail", []string{}
	}
	generation, err := p.Objects.CreateFixed(ctx, key, "application/json", body)
	if err == nil {
		var back []byte
		back, err = p.Objects.Read(ctx, key, generation)
		if err == nil && !bytes.Equal(back, body) {
			err = errors.New("probe object bytes differ")
		}
	}
	if err != nil {
		return "fail", []string{}
	}
	return "pass", []string{"gs://" + p.Bucket + "/" + key + "#" + strconv.FormatInt(generation, 10)}
}
