package bootstrap

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxBodyBytes bounds the request body.
const MaxBodyBytes = 64 << 10

// Wire format. SPEC-QUESTION: COMMON defines the route and the checks but not
// the request and response fields of POST /internal/workload-certificates.
// These names stay provisional until a separate contract PR fixes them.
type request struct {
	CSR   string `json:"csr"`
	Token string `json:"token"`
}

type response struct {
	Certificate      string   `json:"certificate"`       // PEM leaf
	CertificateChain []string `json:"certificate_chain"` // PEM, issuer first
	Serial           string   `json:"serial"`
	ExpiresAt        string   `json:"expires_at"` // RFC 3339 UTC
}

type errorBody struct {
	RequestID   string   `json:"request_id"`
	ReasonCodes []string `json:"reason_codes"`
}

// Handler serves POST /internal/workload-certificates. It never reads
// X-Agentarium-Peer-Identity: the SAN comes only from the token review.
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := newRequestID()
		if r.Method != http.MethodPost {
			writeError(w, reqID, http.StatusMethodNotAllowed, nil)
			return
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			writeError(w, reqID, http.StatusUnsupportedMediaType, []string{"SCHEMA_INVALID"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
		if err != nil {
			writeError(w, reqID, http.StatusBadRequest, []string{"SCHEMA_INVALID"})
			return
		}
		if len(body) > MaxBodyBytes {
			writeError(w, reqID, http.StatusRequestEntityTooLarge, []string{"BODY_TOO_LARGE"})
			return
		}
		var in request
		if err := decodeStrict(body, &in); err != nil {
			writeError(w, reqID, http.StatusUnprocessableEntity, []string{"SCHEMA_INVALID"})
			return
		}
		cert, err := s.Issue(r.Context(), in.Token, []byte(in.CSR))
		switch {
		case err == nil:
			out := response{
				Certificate:      cert.LeafPEM,
				CertificateChain: cert.ChainPEM,
				Serial:           cert.Serial,
				ExpiresAt:        cert.NotAfter.UTC().Format(time.RFC3339),
			}
			if out.CertificateChain == nil {
				out.CertificateChain = []string{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		case errors.Is(err, ErrBadRequest):
			writeError(w, reqID, http.StatusUnprocessableEntity, []string{"SCHEMA_INVALID"})
		case errors.Is(err, ErrUnauthenticated):
			// SPEC-QUESTION: COMMON has no code for "not a registered or live
			// workload"; AUTH_REQUIRED (401) is the closest common code.
			writeError(w, reqID, http.StatusUnauthorized, []string{"AUTH_REQUIRED"})
		default:
			w.Header().Set("Retry-After", "2")
			writeError(w, reqID, http.StatusServiceUnavailable, []string{unavailableCode(err)})
		}
	})
}

// unavailableCode picks the COMMON reason code for a 503 by the dependency
// that failed.
func unavailableCode(err error) string {
	switch {
	case errors.Is(err, ErrIssuerUnavailable):
		// SPEC-QUESTION: COMMON has no code for "CAS did not issue".
		// CREDENTIAL_UNAVAILABLE (503, "lookup failure") is the closest dictionary
		// code, although COMMON lists TASK-06 as its owner.
		return "CREDENTIAL_UNAVAILABLE"
	case errors.Is(err, ErrClusterUnavailable):
		// SPEC-QUESTION: COMMON has no code for a failed TokenReview or
		// Pod/Node get. STATE_STORE_UNAVAILABLE ("fact lookup failure") is the
		// closest dictionary code.
		return "STATE_STORE_UNAVAILABLE"
	default:
		// ErrStoreUnavailable, and any error Issue does not classify.
		return "STATE_STORE_UNAVAILABLE"
	}
}

// decodeStrict accepts exactly one JSON object with the fields of v, no
// unknown, duplicate or case-only-different keys, valid UTF-8 and nothing
// after it (COMMON "external bodies: strict schema, extra fields refused").
func decodeStrict(body []byte, v *request) error {
	if !utf8.Valid(body) {
		return errors.New("invalid utf-8")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("body is not an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := kt.(string)
		if key != "csr" && key != "token" {
			return fmt.Errorf("unknown field %q", key)
		}
		if seen[key] {
			return fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = true
		var val string
		if err := dec.Decode(&val); err != nil {
			return fmt.Errorf("field %q: %w", key, err)
		}
		if key == "csr" {
			v.CSR = val
		} else {
			v.Token = val
		}
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	if !seen["csr"] || !seen["token"] {
		return errors.New("missing field")
	}
	return nil
}

func writeError(w http.ResponseWriter, reqID string, status int, codes []string) {
	if codes == nil {
		codes = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{RequestID: reqID, ReasonCodes: codes})
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
