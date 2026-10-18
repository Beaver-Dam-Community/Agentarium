package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Session kinds (COMMON enum session_kind).
const (
	KindUser    = "user"
	KindService = "service"
)

// Caller is a request authenticated by its client certificate and session
// token (TASK-04 3.1 caller authentication).
type Caller struct {
	Kind               string // user or service
	SAN                string // verified client certificate SAN
	Namespace, KSA     string
	SessionID          string // session_id, or service_session_id
	AuthenticatedActor string
	Tenant             string
	WorkloadID         string // user sessions: "<namespace>/<ksa>"
	NodeUID            string // node of the caller's certificate (user sessions)
	Profile            string // service sessions
}

var authRequired = fail(http.StatusUnauthorized, "AUTH_REQUIRED", "authentication failed")

// Authenticate maps a verified client certificate and a bearer token to a
// Caller (TASK-04 3.1):
//   - the certificate's serial must match an unrevoked, unexpired
//     identity.issued_certificates row with the same SAN, issued to an
//     enabled registered workload;
//   - SHA-256(token) must be an unrevoked identity.session_tokens row whose
//     bound_identity is that SAN;
//   - a user session must be claimed by that workload and unexpired; a
//     service session must be active, unexpired and owned by
//     service:<namespace>/<ksa>.
//
// Every failure is 401 AUTH_REQUIRED, before any policy evaluation (COMMON
// error defaults: an expired session token never reaches Rego).
func (s *Service) Authenticate(ctx context.Context, leaf *x509.Certificate, token string) (Caller, error) {
	if leaf == nil || len(leaf.URIs) != 1 || leaf.SerialNumber == nil || token == "" {
		return Caller{}, authRequired
	}
	san := leaf.URIs[0].String()
	ns, ksa, podSAN, err := parseSAN(san)
	if err != nil {
		return Caller{}, authRequired
	}
	digest := sha256.Sum256([]byte(token))
	c := Caller{SAN: san, Namespace: ns, KSA: ksa}
	err = s.readTx(ctx, func(tx pgx.Tx) error {
		var role string
		var node *string
		err := tx.QueryRow(ctx, `
SELECT w.role, c.node_uid::text
FROM identity.issued_certificates c
JOIN identity.registered_workloads w USING (namespace, ksa)
WHERE c.serial = $1 AND c.san_uri = $2 AND c.namespace = $3 AND c.ksa = $4
  AND c.revoked_at IS NULL AND c.expires_at > statement_timestamp() AND w.enabled`,
			hex.EncodeToString(leaf.SerialNumber.Bytes()), san, ns, ksa).Scan(&role, &node)
		if errors.Is(err, pgx.ErrNoRows) {
			return authRequired
		}
		if err != nil {
			return err
		}
		var userSession, serviceSession *string
		var bound string
		err = tx.QueryRow(ctx, `
SELECT session_id::text, service_session_id::text, bound_identity
FROM identity.session_tokens WHERE token_digest = $1 AND revoked_at IS NULL`, digest[:]).Scan(&userSession, &serviceSession, &bound)
		if errors.Is(err, pgx.ErrNoRows) {
			return authRequired
		}
		if err != nil {
			return err
		}
		if bound != san {
			return authRequired
		}
		switch {
		case userSession != nil && role == "runtime" && podSAN:
			var workload, state string
			var live bool
			err = tx.QueryRow(ctx, `
SELECT authenticated_actor, tenant, workload_id, state, expires_at > statement_timestamp()
FROM identity.sessions WHERE session_id = $1`, *userSession).Scan(&c.AuthenticatedActor, &c.Tenant, &workload, &state, &live)
			if err != nil {
				return err
			}
			if state != "claimed" || !live || workload != ns+"/"+ksa {
				return authRequired
			}
			c.Kind, c.SessionID, c.WorkloadID = KindUser, *userSession, workload
			if node != nil {
				c.NodeUID = *node
			}
		case serviceSession != nil && role == "service":
			var state string
			var live bool
			err = tx.QueryRow(ctx, `
SELECT authenticated_actor, tenant, profile, state, expires_at > statement_timestamp()
FROM identity.service_sessions WHERE service_session_id = $1`, *serviceSession).Scan(&c.AuthenticatedActor, &c.Tenant, &c.Profile, &state, &live)
			if err != nil {
				return err
			}
			if state != "active" || !live || c.AuthenticatedActor != "service:"+ns+"/"+ksa {
				return authRequired
			}
			c.Kind, c.SessionID = KindService, *serviceSession
		default:
			return authRequired
		}
		return nil
	})
	if err != nil {
		return Caller{}, err
	}
	return c, nil
}

// LiveCertificate checks a verified client certificate without a session
// token (the runtime relays, relay.go): its serial must be an unrevoked,
// unexpired identity.issued_certificates row with the same SAN, issued to an
// enabled registered workload, as in Authenticate. Failure is 401
// AUTH_REQUIRED.
func (s *Service) LiveCertificate(ctx context.Context, leaf *x509.Certificate) error {
	if leaf == nil || len(leaf.URIs) != 1 || leaf.SerialNumber == nil {
		return authRequired
	}
	san := leaf.URIs[0].String()
	ns, ksa, _, err := parseSAN(san)
	if err != nil {
		return authRequired
	}
	return s.readTx(ctx, func(tx pgx.Tx) error {
		var one int
		err := tx.QueryRow(ctx, `
SELECT 1
FROM identity.issued_certificates c
JOIN identity.registered_workloads w USING (namespace, ksa)
WHERE c.serial = $1 AND c.san_uri = $2 AND c.namespace = $3 AND c.ksa = $4
  AND c.revoked_at IS NULL AND c.expires_at > statement_timestamp() AND w.enabled`,
			hex.EncodeToString(leaf.SerialNumber.Bytes()), san, ns, ksa).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return authRequired
		}
		return err
	})
}

// parseSAN reads spiffe://agentarium.internal/ns/<ns>/sa/<ksa>[/pod/<uid>]
// and reports whether it is a Pod SAN.
func parseSAN(san string) (ns, ksa string, pod bool, err error) {
	rest, ok := strings.CutPrefix(san, "spiffe://agentarium.internal/ns/")
	if !ok {
		return "", "", false, fmt.Errorf("SAN %q is not a workload SAN", san)
	}
	p := strings.Split(rest, "/")
	if !(len(p) == 3 || len(p) == 5) || p[1] != "sa" || p[0] == "" || p[2] == "" ||
		(len(p) == 5 && (p[3] != "pod" || p[4] == "")) {
		return "", "", false, fmt.Errorf("SAN %q is malformed", san)
	}
	return p[0], p[2], len(p) == 5, nil
}

// owns reports whether the caller may read or re-evaluate an action of
// sessionID: the session owner, or the service session itself (TASK-04 chapter 4).
func (c Caller) owns(sessionKind, sessionID string) bool {
	return c.Kind == sessionKind && c.SessionID == sessionID
}

// rfc3339 formats a database time for the OPA input.
func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
