package dispatch

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ServiceCaller is a service principal authenticated by its client
// certificate and a service-session token bound to that certificate's SAN.
type ServiceCaller struct {
	SAN              string
	ServiceSessionID string
	Profile          string
	ChangeID         string // "" unless the session has change_id scope
}

// AuthenticateService maps a verified client certificate and a bearer token
// to a service session (TASK-03 3.4 service sessions). The certificate's serial must
// match an unrevoked, unexpired identity.issued_certificates row with the
// same SAN, issued to a registered, enabled service workload. The token's
// SHA-256 digest must be an unrevoked identity.session_tokens row of a
// service session, bound to that SAN, whose caller_principal is the
// workload's service_principal, active and unexpired. Any failure is 401
// AUTH_REQUIRED, as for an expired session token (TASK-03 3.4).
func (s *Service) AuthenticateService(ctx context.Context, leaf *x509.Certificate, token string) (ServiceCaller, error) {
	denied := fail(http.StatusUnauthorized, "AUTH_REQUIRED", "not a current service session of this certificate")
	if leaf == nil || len(leaf.URIs) != 1 || leaf.SerialNumber == nil || token == "" {
		return ServiceCaller{}, denied
	}
	san := leaf.URIs[0].String()
	ns, ksa, err := parseSAN(san)
	if err != nil {
		return ServiceCaller{}, denied
	}
	digest := sha256.Sum256([]byte(token))
	c := ServiceCaller{SAN: san}
	var change *string
	err = s.Pool.QueryRow(ctx, `
SELECT s.service_session_id::text, s.profile, s.change_id::text
FROM identity.issued_certificates c
JOIN identity.registered_workloads w USING (namespace, ksa)
JOIN identity.session_tokens t ON t.bound_identity = c.san_uri
JOIN identity.service_sessions s ON s.service_session_id = t.service_session_id
WHERE c.serial = $1 AND c.san_uri = $2 AND c.namespace = $3 AND c.ksa = $4
  AND c.revoked_at IS NULL AND c.expires_at > statement_timestamp()
  AND w.role = 'service' AND w.enabled AND w.service_principal = s.caller_principal
  AND t.token_digest = $5 AND t.revoked_at IS NULL
  AND s.state = 'active' AND s.expires_at > statement_timestamp()`,
		hex.EncodeToString(leaf.SerialNumber.Bytes()), san, ns, ksa, digest[:]).Scan(&c.ServiceSessionID, &c.Profile, &change)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceCaller{}, denied
	}
	if err != nil {
		return ServiceCaller{}, err
	}
	if change != nil {
		c.ChangeID = *change
	}
	return c, nil
}

// ProbeRequest is the POST /internal/dispatch/activation-probes body (COMMON
// API implementation contract).
type ProbeRequest struct {
	ChangeID         string `json:"change_id"`
	ClientRequestKey string `json:"client_request_key"`
	TargetEpoch      int64  `json:"target_epoch"`
}

// ClientAction.client_request_key (COMMON actions, approvals and decisions).
var clientKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

func (r ProbeRequest) valid() bool {
	return isUUID(r.ChangeID) && clientKeyRE.MatchString(r.ClientRequestKey) && r.TargetEpoch > 0
}

// ProbeResult answers a registration.
type ProbeResult struct {
	ActivationProbeID string    `json:"activation_probe_id"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// RegisterProbe registers an activation probe before the releaser submits
// its action (COMMON activation-probe-only dispatch, step 2). The caller must
// be an activation_probe service session with the same change_id scope, and
// the change's policy_activation hold must be open. The second return value
// is true for a new registration and false for a replay of the same
// (service session, client_request_key, change_id, target_epoch), which
// returns the stored row without a second event.
//
// SPEC-QUESTION: COMMON gives the probe no lifetime. expires_at is the
// service session's expires_at (activation_probe TTL 10 min), so a probe
// never outlives the session that registered it. TASK-14 3.3 step 2 instead
// has the releaser send action_id and expires_at; COMMON and TASK-03 (no
// action_id at registration) are implemented here.
func (s *Service) RegisterProbe(ctx context.Context, c ServiceCaller, req ProbeRequest) (*ProbeResult, bool, error) {
	if !req.valid() {
		return nil, false, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "malformed activation probe request")
	}
	if c.Profile != "activation_probe" || c.ChangeID != req.ChangeID {
		return nil, false, fail(http.StatusForbidden, "SERVICE_SCOPE_DENIED", "caller is not an activation_probe session of this change")
	}
	var out *ProbeResult
	var created bool
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// holds FOR SHARE
		if _, err := s.health().LockActivationHold(ctx, tx, req.ChangeID); err != nil {
			if errors.Is(err, ErrNotFound) {
				// SPEC-QUESTION: COMMON has no code for "the change has no
				// open activation hold"; it is answered as a resource outside
				// the caller's scope.
				return fail(http.StatusNotFound, "RESOURCE_NOT_FOUND", "the change has no open policy_activation hold")
			}
			return depErr(err, "CONTROL_HEALTH_UNAVAILABLE", "holds")
		}
		// service_sessions FOR SHARE: the session may have ended since the
		// unlocked authentication read.
		var live bool
		var expires time.Time
		err := tx.QueryRow(ctx, `
SELECT state = 'active' AND expires_at > statement_timestamp() AND profile = 'activation_probe' AND change_id = $2, expires_at
FROM identity.service_sessions WHERE service_session_id = $1 FOR SHARE`, c.ServiceSessionID, req.ChangeID).Scan(&live, &expires)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !live) {
			return fail(http.StatusUnauthorized, "AUTH_REQUIRED", "service session ended")
		}
		if err != nil {
			return err
		}
		id := uuid.NewString()
		tag, err := tx.Exec(ctx, `
INSERT INTO coordinator.activation_probes (activation_probe_id, change_id, service_session_id, client_request_key, target_epoch, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (service_session_id, client_request_key) DO NOTHING`,
			id, req.ChangeID, c.ServiceSessionID, req.ClientRequestKey, req.TargetEpoch, expires)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var change string
			var epoch int64
			out = &ProbeResult{}
			if err := tx.QueryRow(ctx, `
SELECT activation_probe_id::text, change_id::text, target_epoch, expires_at FROM coordinator.activation_probes
WHERE service_session_id = $1 AND client_request_key = $2`, c.ServiceSessionID, req.ClientRequestKey).Scan(
				&out.ActivationProbeID, &change, &epoch, &out.ExpiresAt); err != nil {
				return err
			}
			if change != req.ChangeID || epoch != req.TargetEpoch {
				// SPEC-QUESTION: COMMON defines CLIENT_KEY_BODY_CONFLICT for
				// POST /v1/actions (TASK-04); it is reused for a registration
				// key replayed with another body.
				return conflict("CLIENT_KEY_BODY_CONFLICT", "client_request_key is registered with another body")
			}
			return nil
		}
		if err := s.audit().Append(ctx, tx, Event{Type: "activation_probe_registered", Payload: map[string]any{
			"activation_probe_id": id, "change_id": req.ChangeID, "service_session_id": c.ServiceSessionID,
			"client_request_key": req.ClientRequestKey, "target_epoch": req.TargetEpoch,
		}}); err != nil {
			return depErr(err, "STATE_STORE_UNAVAILABLE", "audit_append")
		}
		out, created = &ProbeResult{ActivationProbeID: id, ExpiresAt: expires}, true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, created, nil
}

// probeUsable reports whether the decision's activation probe lets it pass
// (COMMON reservation transaction): the registration exists, belongs to the
// decision's service session, is bound to the decision's action, targets the
// active epoch and is unexpired. lock reads it FOR SHARE.
func (s *Service) probeUsable(ctx context.Context, tx pgx.Tx, dec Decision, active ActivePolicy, lock bool) (bool, error) {
	if dec.DecisionBasis != "activation_probe" || !isUUID(dec.ActivationProbeID) {
		return false, nil
	}
	q := `SELECT service_session_id::text, action_id::text, target_epoch, expires_at > statement_timestamp()
FROM coordinator.activation_probes WHERE activation_probe_id = $1`
	if lock {
		q += " FOR SHARE"
	}
	var sess string
	var action *string
	var epoch int64
	var unexpired bool
	err := tx.QueryRow(ctx, q, dec.ActivationProbeID).Scan(&sess, &action, &epoch, &unexpired)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return sess == dec.ServiceSessionID && action != nil && *action == dec.ActionID && epoch == active.Epoch && unexpired, nil
}
