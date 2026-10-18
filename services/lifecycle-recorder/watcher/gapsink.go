package watcher

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

const gapPath = "/internal/control-health/observation-gaps"
const pendingGapFile = "gap-pending.json"

// GapRequest is the POST /internal/control-health/observation-gaps body
// (TASK-10 3.6 "receiving watch history gaps", #178).
type GapRequest struct {
	Scope string  `json:"scope"`
	Gap   gapBody `json:"gap"`
}
type gapBody struct {
	GapID         string            `json:"gap_id"`
	Stage         string            `json:"stage"`
	Reason        string            `json:"reason"`
	SourceEpoch   string            `json:"source_epoch"`
	StartAt       string            `json:"start_at"`
	EndAt         string            `json:"end_at"`
	LossCount     *int64            `json:"loss_count"`
	CountQuality  string            `json:"count_quality"`
	RecoveryState string            `json:"recovery_state"`
	EvidenceRefs  []json.RawMessage `json:"evidence_refs"`
}

// HTTPGapSink durably records a watch-history gap with control-health. The
// request (with its producer gap_id) is fsynced in the watcher directory
// before the first attempt and resent byte-for-byte until control-health
// acknowledges it, including after a restart. Only then does Report return
// nil, so the producer never relists over an unrecorded gap.
type HTTPGapSink struct {
	Directory string
	Origin    string
	// Client must authenticate control-health's service identity and present
	// the pod-watcher certificate.
	Client *http.Client
}

type gapAck struct {
	GapID      string `json:"gap_id"`
	Result     string `json:"result"`
	RecordedAt string `json:"recorded_at"`
}

// PermanentGapError means control-health refused the gap (for example 403
// scope or 409 EVENT_ID_CONFLICT) or answered with an invalid
// acknowledgement. The pending request stays on disk.
type PermanentGapError struct{ Status int }

func (e *PermanentGapError) Error() string {
	return fmt.Sprintf("control-health refused watch-history gap: HTTP %d", e.Status)
}

func writeDurable(dir, name string, b []byte) error {
	f, err := os.CreateTemp(dir, name+".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Report implements Config.GapSink.
func (s *HTTPGapSink) Report(ctx context.Context, g Gap) error {
	if s.Directory == "" || s.Origin == "" || s.Client == nil {
		return errors.New("gap sink requires directory, control-health origin and client")
	}
	if g.Reason != "WATCH_HISTORY_EXPIRED" || g.Epoch == "" || g.Scope == "" || g.LastCommittedAt.IsZero() || g.DetectedAt.IsZero() {
		return errors.New("incomplete watch-history gap")
	}
	if g.LastCommittedAt.After(g.DetectedAt) {
		g.LastCommittedAt = g.DetectedAt // clock skew: never send start_at > end_at
	}
	path := filepath.Join(s.Directory, pendingGapFile)
	// A request left by an earlier attempt or process is delivered first,
	// unchanged. It is the same detection when scope/epoch/start match.
	if b, err := os.ReadFile(path); err == nil {
		var old GapRequest
		if err := json.Unmarshal(b, &old); err != nil {
			return errors.New("invalid pending gap request; retained for investigation")
		}
		if err := s.deliver(ctx, b, old.Gap.GapID); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := syncDir(s.Directory); err != nil {
			return err
		}
		if old.Scope == g.Scope && old.Gap.SourceEpoch == g.Epoch && old.Gap.StartAt == g.LastCommittedAt.UTC().Format(time.RFC3339Nano) {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	req := GapRequest{Scope: g.Scope, Gap: gapBody{GapID: uuid.NewString(), Stage: "lifecycle_capture", Reason: g.Reason, SourceEpoch: g.Epoch,
		StartAt: g.LastCommittedAt.UTC().Format(time.RFC3339Nano), EndAt: g.DetectedAt.UTC().Format(time.RFC3339Nano),
		CountQuality: "unknown", RecoveryState: "unrecoverable", EvidenceRefs: []json.RawMessage{}}}
	b, err := canonical.CanonicalJSON(req)
	if err != nil {
		return err
	}
	if err := writeDurable(s.Directory, pendingGapFile, b); err != nil {
		return err
	}
	if err := s.deliver(ctx, b, req.Gap.GapID); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDir(s.Directory)
}

// deliver retries transport/5xx failures with backoff until ctx ends.
func (s *HTTPGapSink) deliver(ctx context.Context, body []byte, id string) error {
	delay := time.Second
	for {
		err := s.post(ctx, body, id)
		var permanent *PermanentGapError
		if err == nil || errors.As(err, &permanent) {
			return err
		}
		if err := wait(ctx, delay); err != nil {
			return err
		}
		delay = min(2*delay, 30*time.Second)
	}
}

func (s *HTTPGapSink) post(ctx context.Context, body []byte, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Origin+gapPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("control-health HTTP %d", resp.StatusCode)
	default:
		return &PermanentGapError{resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil || canonical.CheckJSONForJCS(raw) != nil {
		return &PermanentGapError{resp.StatusCode}
	}
	var ack gapAck
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	want := "created"
	if resp.StatusCode == http.StatusOK {
		want = "existing"
	}
	if d.Decode(&ack) != nil || ack.GapID != id || ack.Result != want {
		return &PermanentGapError{resp.StatusCode}
	}
	if _, err := time.Parse(time.RFC3339Nano, ack.RecordedAt); err != nil {
		return &PermanentGapError{resp.StatusCode}
	}
	return nil
}

// ControlHealthSAN is the only identity the gap sink accepts as receiver.
const ControlHealthSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"

// NewControlHealthClient verifies the exact control-health URI SAN with the
// given roots and presents the pod-watcher client certificate from base.
func NewControlHealthClient(base *tls.Config) (*http.Client, error) {
	if base == nil || base.RootCAs == nil || (len(base.Certificates) == 0 && base.GetClientCertificate == nil) {
		return nil, errors.New("verified mTLS configuration required")
	}
	cfg := base.Clone()
	roots := base.RootCAs.Clone()
	cfg.MinVersion = max(cfg.MinVersion, tls.VersionTLS13)
	cfg.InsecureSkipVerify = true // URI identity is verified below.
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("missing control-health certificate")
		}
		leaf := cs.PeerCertificates[0]
		if len(leaf.URIs) != 1 || leaf.URIs[0].String() != ControlHealthSAN {
			return errors.New("incorrect control-health identity")
		}
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		return err
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: cfg, DisableKeepAlives: true, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
