package ingest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

var (
	ErrForbidden = errors.New("producer not allowed")
	ErrSchema    = errors.New("invalid event")
)

type Ack struct {
	EventID    string    `json:"event_id"`
	Result     string    `json:"result"`
	ReceivedAt time.Time `json:"received_at"`
}

// Store must return only after COMMIT. Conflict recording uses a separate
// transaction after rollback; an undurable conflict is an error, never an ack.
type Store interface {
	Append(context.Context, Event, []byte) (Ack, error)
}

// Authorizer resolves SAN ns/sa through registered_workloads and the explicit
// source registration. Neither headers nor unregistered body values are identity.
type Authorizer interface {
	Authorize(context.Context, string, string) error
}

type Handler struct {
	Store      Store
	Authorizer Authorizer
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/internal/audit/events" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	requestID := uuid.NewString()
	san, err := peerSAN(r.TLS)
	if err != nil {
		writeError(w, 401, requestID, "AUTH_REQUIRED")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, canonical.MaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, 413, requestID, "BODY_TOO_LARGE")
		} else {
			writeError(w, 422, requestID, "SCHEMA_INVALID")
		}
		return
	}
	event, err := Decode(raw)
	if err != nil {
		writeError(w, 422, requestID, "SCHEMA_INVALID")
		return
	}
	if err = h.Authorizer.Authorize(r.Context(), san, event.SourceID); err != nil {
		if errors.Is(err, ErrForbidden) {
			writeError(w, 403, requestID, "")
		} else {
			writeError(w, 503, requestID, "STATE_STORE_UNAVAILABLE")
		}
		return
	}
	ack, err := h.Store.Append(r.Context(), event, raw)
	writeAck(w, requestID, event, ack, err)
}
func writeError(w http.ResponseWriter, status int, id, code string) {
	w.Header().Set("Content-Type", "application/json")
	if status == 503 {
		w.Header().Set("Retry-After", "2")
	}
	w.WriteHeader(status)
	codes := []string{}
	if code != "" {
		codes = append(codes, code)
	}
	_ = json.NewEncoder(w).Encode(struct {
		RequestID   string   `json:"request_id"`
		ReasonCodes []string `json:"reason_codes"`
	}{id, codes})
}
func peerSAN(state *tls.ConnectionState) (string, error) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", ErrForbidden
	}
	return ServiceSAN(state.VerifiedChains[0][0])
}
func ServiceSAN(cert *x509.Certificate) (string, error) {
	// Business producers use a single service SAN. Workload and node identities
	// have separate ingress contracts and cannot submit through this endpoint.
	if len(cert.URIs) != 1 {
		return "", ErrForbidden
	}
	u := cert.URIs[0]
	ns, ksa, ok := ParseServiceSAN(u.String())
	if !ok || ns == "agent-exec" || ksa == "" {
		return "", ErrForbidden
	}
	return u.String(), nil
}
func ParseServiceSAN(s string) (string, string, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "spiffe" || u.Host != "agentarium.internal" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.RawPath != "" {
		return "", "", false
	}
	p := strings.Split(u.Path, "/")
	if len(p) != 5 || p[1] != "ns" || p[3] != "sa" || p[2] == "" || p[4] == "" {
		return "", "", false
	}
	return p[2], p[4], true
}
