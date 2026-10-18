package health

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

type Backend interface {
	Put(context.Context, Peer, Lease) (LeaseAck, error)
	Get(context.Context, Peer, string, string) (Snapshot, error)
	ReportProbe(context.Context, Peer, ProbeRelay, ProbeReport) (ProbeAck, error)
	ReleaseHold(context.Context, Peer, string, ReleaseRequest, ConsoleContext) (ReleaseAck, error)
	ReceiveWatchGap(context.Context, Peer, WatchGapRequest) (WatchGapAck, error)
	RequestHold(context.Context, Peer, HoldRequest) (HoldAck, error)
	OwnedHolds(context.Context, Peer, string) (OwnedHolds, error)
}
type Handler struct {
	Backend Backend
	// Workers serves the TASK-10 3.5a/3.5b work-readiness API; nil answers 503.
	Workers WorkerBackend
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := uuid.NewString()
	peer, err := VerifiedPeer(r.TLS)
	if err != nil {
		writeError(w, 401, id, "AUTH_REQUIRED")
		return
	}
	// A Pod-bound certificate outside agent-exec is the agent-adapters probe
	// runner's; it reports probe results directly and calls nothing else.
	if peer.PodUID != "" && (r.Method != "POST" || r.URL.Path != "/internal/control-health/probe-results") {
		writeError(w, 401, id, "AUTH_REQUIRED")
		return
	}
	if h.serveWorkers(w, r, id, peer) {
		return
	}
	var result any
	switch {
	case r.Method == "POST" && r.URL.Path == "/internal/control-health/leases":
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, canonical.MaxBodyBytes))
		if e != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(e, &tooLarge) {
				writeError(w, 413, id, "BODY_TOO_LARGE")
			} else {
				writeError(w, 422, id, "SCHEMA_INVALID")
			}
			return
		}
		lease, e := DecodeLease(raw)
		if e != nil {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return
		}
		result, err = h.Backend.Put(r.Context(), peer, lease)
	case r.Method == "POST" && r.URL.Path == "/internal/control-health/probe-results":
		raw, ok := readBody(w, r, id)
		if !ok {
			return
		}
		report, e := DecodeProbeReport(raw)
		if e != nil {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return
		}
		relay := ProbeRelay{SAN: r.Header.Values(PeerIdentityHeader), Serial: r.Header.Values(PeerSerialHeader)}
		result, err = h.Backend.ReportProbe(r.Context(), peer, relay, report)
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/internal/holds/") && strings.HasSuffix(r.URL.Path, "/release"):
		holdID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/internal/holds/"), "/release")
		if !canonicalUUID(holdID) || r.URL.RawQuery != "" {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return
		}
		raw, ok := readBody(w, r, id)
		if !ok {
			return
		}
		release, e := DecodeReleaseRequest(raw)
		if e != nil {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return
		}
		console := ConsoleContext{Actor: r.Header.Get("X-Agentarium-Console-Actor"), Roles: ConsoleRoles(r.Header.Get("X-Agentarium-Console-Roles"))}
		result, err = h.Backend.ReleaseHold(r.Context(), peer, holdID, release, console)
	case r.Method == "POST" && r.URL.Path == "/internal/control-health/observation-gaps":
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, canonical.MaxBodyBytes))
		if e != nil {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return
		}
		gap, e := DecodeWatchGap(raw)
		if e != nil {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return
		}
		ack, e := h.Backend.ReceiveWatchGap(r.Context(), peer, gap)
		if e == nil {
			status := http.StatusCreated
			if ack.Result == "existing" {
				status = http.StatusOK
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(ack)
			return
		}
		if errors.Is(e, ErrConflict) {
			writeError(w, 409, id, "EVENT_ID_CONFLICT")
			return
		}
		err = e
	case r.Method == "POST" && r.URL.Path == "/internal/holds":
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, canonical.MaxBodyBytes))
		if e != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(e, &tooLarge) {
				writeError(w, 413, id, "BODY_TOO_LARGE")
			} else {
				writeError(w, 422, id, "SCHEMA_INVALID")
			}
			return
		}
		hold, e := DecodeHoldRequest(raw)
		if e != nil {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return
		}
		result, err = h.Backend.RequestHold(r.Context(), peer, hold)
	case r.Method == "GET" && r.URL.Path == "/internal/holds":
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil || len(q) != 1 || len(q["owner_component"]) != 1 || q.Get("owner_component") == "" || len(q.Get("owner_component")) > 256 {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return
		}
		result, err = h.Backend.OwnedHolds(r.Context(), peer, q.Get("owner_component"))
	case r.Method == "GET" && r.URL.Path == "/internal/control-health":
		q, e := url.ParseQuery(r.URL.RawQuery)
		if e != nil || len(q) != 2 || len(q["scope"]) != 1 || len(q["scope_id"]) != 1 || !ValidScopeID(q.Get("scope"), q.Get("scope_id")) {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return
		}
		result, err = h.Backend.Get(r.Context(), peer, q.Get("scope"), q.Get("scope_id"))
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, ErrForbidden):
			if r.URL.Path == "/internal/holds" && r.Method == "GET" {
				writeError(w, 403, id, CodeHoldRequestDenied)
				return
			}
			if r.URL.Path == "/internal/holds" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(HoldAck{Decision: "rejected", ReasonCodes: []string{CodeHoldRequestDenied}})
				return
			}
			writeError(w, 403, id, "")
		case errors.Is(err, ErrInvalid):
			writeError(w, 422, id, "SCHEMA_INVALID")
		case errors.Is(err, ErrConflict):
			writeError(w, 409, id, "")
		case errors.Is(err, ErrNotFound):
			writeError(w, 404, id, "RESOURCE_NOT_FOUND")
		default:
			writeError(w, 503, id, "CONTROL_HEALTH_UNAVAILABLE")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/internal/control-health/probe-results" {
		w.WriteHeader(http.StatusCreated)
	}
	_ = json.NewEncoder(w).Encode(result)
}
func readBody(w http.ResponseWriter, r *http.Request, id string) ([]byte, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, canonical.MaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, 413, id, "BODY_TOO_LARGE")
		} else {
			writeError(w, 422, id, "SCHEMA_INVALID")
		}
		return nil, false
	}
	return raw, true
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
func VerifiedPeer(state *tls.ConnectionState) (Peer, error) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return Peer{}, ErrForbidden
	}
	cert := state.VerifiedChains[0][0]
	if len(cert.URIs) != 1 || cert.SerialNumber == nil {
		return Peer{}, ErrForbidden
	}
	u := cert.URIs[0]
	p := strings.Split(u.Path, "/")
	// Service SAN .../ns/<ns>/sa/<ksa>, or a Pod-bound SAN with /pod/<uid>.
	// agent-exec never connects directly (TASK-06: gateway relay only).
	pod := len(p) == 7 && p[5] == "pod" && canonicalUUID(p[6])
	if u.Scheme != "spiffe" || u.Host != "agentarium.internal" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (len(p) != 5 && !pod) || p[1] != "ns" || p[3] != "sa" || p[2] == "" || p[2] == "agent-exec" || p[4] == "" {
		return Peer{}, ErrForbidden
	}
	peer := Peer{SAN: u.String(), Serial: hex.EncodeToString(cert.SerialNumber.Bytes())}
	if pod {
		peer.PodUID = p[6]
	}
	return peer, nil
}
