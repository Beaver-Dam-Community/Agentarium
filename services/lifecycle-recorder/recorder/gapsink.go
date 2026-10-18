package recorder

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

// GapRequest is the runtime form of POST /internal/control-health/
// observation-gaps (TASK-10 3.6, PR #207): node scope, node/boot bound to the
// recorder's certificate.
type GapRequest struct {
	Scope string  `json:"scope"`
	Gap   gapBody `json:"gap"`
}
type gapBody struct {
	GapID         string            `json:"gap_id"`
	Stage         string            `json:"stage"`
	Reason        string            `json:"reason"`
	SourceEpoch   string            `json:"source_epoch"`
	NodeUID       string            `json:"node_uid"`
	BootID        string            `json:"boot_id"`
	StartAt       string            `json:"start_at"`
	EndAt         string            `json:"end_at"`
	LossCount     *int64            `json:"loss_count"`
	CountQuality  string            `json:"count_quality"`
	RecoveryState string            `json:"recovery_state"`
	EvidenceRefs  []json.RawMessage `json:"evidence_refs"`
}

// PermanentGapError is a refusal (403/409/422 or an invalid ACK); the pending
// request stays on disk for the operator.
type PermanentGapError struct{ Status int }

func (e *PermanentGapError) Error() string {
	return fmt.Sprintf("control-health refused gap: HTTP %d", e.Status)
}
func (e *PermanentGapError) Permanent() bool { return true }

// HTTPGapSink fsyncs the request with a stable gap_id before the first attempt
// and resends the same bytes until acknowledged, also after a restart.
type HTTPGapSink struct {
	Directory, Origin string
	Client            *http.Client
}

func (s *HTTPGapSink) Report(ctx context.Context, g Gap) error {
	if g.Epoch == "" || !validUUID(g.NodeUID) || g.BootID == "" || g.Start.IsZero() || g.End.IsZero() {
		return errors.New("incomplete runtime gap")
	}
	if g.Start.After(g.End) {
		g.Start = g.End
	}
	path := filepath.Join(s.Directory, pendingGapFile)
	if b, err := os.ReadFile(path); err == nil {
		var old GapRequest
		if json.Unmarshal(b, &old) != nil {
			return &PermanentGapError{Status: 0}
		}
		if old.Gap.NodeUID != g.NodeUID || old.Gap.BootID != g.BootID {
			// TASK-09 3.6: a gap fsynced before a reboot cannot be sent with
			// this boot's certificate (control-health checks node and boot).
			// The new gap replaces it on disk and, on the same node, starts no
			// later than it, so its interval stays covered.
			if old.Gap.NodeUID == g.NodeUID {
				if t, err := time.Parse(time.RFC3339Nano, old.Gap.StartAt); err == nil && t.Before(g.Start) {
					g.Start = t
				}
			}
			return s.send(ctx, g, path)
		}
		if err := s.post(ctx, b, old.Gap.GapID); err != nil {
			return err
		}
		if err := removeSync(s.Directory, path); err != nil {
			return err
		}
		if old.Gap.SourceEpoch == g.Epoch && old.Gap.StartAt == g.Start.UTC().Format(time.RFC3339Nano) {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return s.send(ctx, g, path)
}

// send fsyncs a new request (atomically replacing any pending one) and posts
// it until acknowledged.
func (s *HTTPGapSink) send(ctx context.Context, g Gap, path string) error {
	req := GapRequest{Scope: "node/" + g.NodeUID, Gap: gapBody{GapID: uuid.NewString(), Stage: "lifecycle_capture", Reason: "RUNTIME_RECORD_MISSING", SourceEpoch: g.Epoch, NodeUID: g.NodeUID, BootID: g.BootID,
		StartAt: g.Start.UTC().Format(time.RFC3339Nano), EndAt: g.End.UTC().Format(time.RFC3339Nano), CountQuality: "unknown", RecoveryState: "unrecoverable", EvidenceRefs: []json.RawMessage{}}}
	b, err := canonical.CanonicalJSON(req)
	if err != nil {
		return err
	}
	if err := writeSync(s.Directory, path, b); err != nil {
		return err
	}
	if err := s.post(ctx, b, req.Gap.GapID); err != nil {
		return err
	}
	return removeSync(s.Directory, path)
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
	var ack struct {
		GapID      string `json:"gap_id"`
		Result     string `json:"result"`
		RecordedAt string `json:"recorded_at"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	want := map[int]string{http.StatusCreated: "created", http.StatusOK: "existing"}[resp.StatusCode]
	if d.Decode(&ack) != nil || ack.GapID != id || ack.Result != want {
		return &PermanentGapError{resp.StatusCode}
	}
	if _, err := time.Parse(time.RFC3339Nano, ack.RecordedAt); err != nil {
		return &PermanentGapError{resp.StatusCode}
	}
	return nil
}

func writeSync(dir, path string, b []byte) error {
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0o600); err == nil {
		if _, err = f.Write(b); err == nil {
			err = f.Sync()
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func removeSync(dir, path string) error {
	if err := os.Remove(path); err != nil {
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

// ControlHealthSAN is the only identity accepted as the gap receiver.
const ControlHealthSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"

// NewControlHealthClient verifies the exact control-health URI SAN and
// presents the recorder's client certificate from base.
func NewControlHealthClient(base *tls.Config) (*http.Client, error) {
	if base == nil || base.RootCAs == nil || (len(base.Certificates) == 0 && base.GetClientCertificate == nil) {
		return nil, errors.New("verified mTLS configuration required")
	}
	cfg := base.Clone()
	roots := base.RootCAs.Clone()
	cfg.MinVersion = max(cfg.MinVersion, tls.VersionTLS13)
	cfg.InsecureSkipVerify = true // the URI identity and chain are verified below
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
