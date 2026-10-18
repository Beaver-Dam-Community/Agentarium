package broker

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

const MaxBody = 1 << 20

func serviceIdentity(cert *x509.Certificate) (string, string, bool) {
	if cert == nil || len(cert.URIs) != 1 {
		return "", "", false
	}
	u := cert.URIs[0]
	if u.Scheme != "spiffe" || u.Host != "agentarium.internal" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return "", "", false
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 5 || parts[1] != "ns" || parts[3] != "sa" || parts[2] != "agent-adapters" || parts[4] == "" {
		return "", "", false
	}
	if escaped := url.PathEscape(parts[4]); escaped != parts[4] {
		return "", "", false
	}
	return parts[2], parts[4], true
}

type Handler struct{ Service *Service }

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	fail := func(status int, reason string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"reason_codes": []string{reason}})
	}
	if r.URL.Path != "/internal/credentials:resolve" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.Service == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		fail(503, "CREDENTIAL_UNAVAILABLE")
		return
	}
	ns, ksa, ok := serviceIdentity(r.TLS.VerifiedChains[0][0])
	if !ok {
		fail(503, "CREDENTIAL_UNAVAILABLE")
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if e != nil {
		fail(413, "BODY_TOO_LARGE")
		return
	}
	if canonical.CheckStrictJSON(body) != nil {
		fail(422, "SCHEMA_INVALID")
		return
	}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !request.valid() {
		fail(422, "SCHEMA_INVALID")
		return
	}
	response, e := h.Service.Resolve(r.Context(), ns, ksa, request)
	if e != nil {
		fail(503, "CREDENTIAL_UNAVAILABLE")
		return
	}
	_ = json.NewEncoder(w).Encode(response)
}
