package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

// PodWatcherSAN is the only caller of the watch history gap route (#178).
const PodWatcherSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher"

// WatchGap is the existing ObservationGap field subset the pod-watcher sends.
type WatchGap struct {
	GapID         string          `json:"gap_id"`
	Stage         string          `json:"stage"`
	Reason        string          `json:"reason"`
	SourceEpoch   string          `json:"source_epoch"`
	StartAt       time.Time       `json:"start_at"`
	EndAt         time.Time       `json:"end_at"`
	LossCount     json.RawMessage `json:"loss_count"`
	CountQuality  string          `json:"count_quality"`
	RecoveryState string          `json:"recovery_state"`
	EvidenceRefs  []string        `json:"evidence_refs"`
}

// WatchGapRequest is POST /internal/control-health/observation-gaps.
type WatchGapRequest struct {
	Scope string   `json:"scope"`
	Gap   WatchGap `json:"gap"`
	// Digest is the JCS SHA-256 of the whole body including scope.
	Digest string `json:"-"`
}

type WatchGapAck struct {
	GapID      string    `json:"gap_id"`
	Result     string    `json:"result"`
	RecordedAt time.Time `json:"recorded_at"`
}

// DecodeWatchGap accepts exactly the #178 body: unknown fields or other fixed
// values are 422. The digest covers the canonical (JCS) body.
func DecodeWatchGap(raw []byte) (WatchGapRequest, error) {
	var r WatchGapRequest
	if len(raw) > canonical.MaxBodyBytes || canonical.CheckStrictJSON(raw) != nil {
		return r, ErrInvalid
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || len(top) != 2 || top["scope"] == nil || top["gap"] == nil {
		return r, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(top["gap"], &fields) != nil || len(fields) != 10 {
		return r, ErrInvalid
	}
	for _, k := range []string{"gap_id", "stage", "reason", "source_epoch", "start_at", "end_at", "loss_count", "count_quality", "recovery_state", "evidence_refs"} {
		if _, ok := fields[k]; !ok {
			return r, ErrInvalid
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return r, ErrInvalid
	}
	g := r.Gap
	if !watchUUID(g.GapID) || r.Scope == "" || len(r.Scope) > 256 || g.Stage != "lifecycle_capture" || g.Reason != "WATCH_HISTORY_EXPIRED" ||
		g.SourceEpoch == "" || len(g.SourceEpoch) > 256 || !bytes.Equal(g.LossCount, []byte("null")) || g.CountQuality != "unknown" ||
		g.RecoveryState != "unrecoverable" || g.StartAt.IsZero() || g.EndAt.IsZero() || g.StartAt.After(g.EndAt) || !watchRefsValid(g.EvidenceRefs) {
		return r, ErrInvalid
	}
	canon, err := canonical.JCS(raw)
	if err != nil {
		return r, ErrInvalid
	}
	sum := sha256.Sum256(canon)
	r.Digest = hex.EncodeToString(sum[:])
	return r, nil
}

func watchRefsValid(refs []string) bool {
	if refs == nil || len(refs) > 256 {
		return false
	}
	for _, ref := range refs {
		if ref == "" || len(ref) > 16384 {
			return false
		}
	}
	return true
}

func watchUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}
