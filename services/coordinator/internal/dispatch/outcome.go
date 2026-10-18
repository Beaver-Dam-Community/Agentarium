package dispatch

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Observation is the COMMON AdapterObservation as the outcome API receives
// it. Optional fields may be absent or null.
type Observation struct {
	AttemptID         string  `json:"attempt_id"`
	LocalAddr         *string `json:"local_addr"`
	LocalPort         *int64  `json:"local_port"`
	PeerAddr          *string `json:"peer_addr"`
	PeerPort          *int64  `json:"peer_port"`
	NetnsInode        *int64  `json:"netns_inode"`
	DialedAddr        *string `json:"dialed_addr"`
	PeerAddrKind      *string `json:"peer_addr_kind"`
	PodUID            *string `json:"pod_uid"`
	ConnectStartedAt  *string `json:"connect_started_at"`
	SendStartedAt     *string `json:"send_started_at"`
	SendFinishedAt    *string `json:"send_finished_at"`
	ResponseAt        *string `json:"response_at"`
	ProviderRequestID *string `json:"provider_request_id"`
	K8sAuditID        *string `json:"k8s_audit_id"`
	WireBodyDigest    *string `json:"wire_body_digest"`
}

// obs is a validated observation in the form it is stored and compared:
// addresses parsed, timestamps in UTC at PostgreSQL's microsecond precision.
type obs struct {
	LocalAddr, PeerAddr, DialedAddr                              *netip.Addr
	LocalPort, PeerPort                                          *int32
	NetnsInode                                                   *int64
	PeerAddrKind, PodUID, ProviderRequestID, K8sAuditID, WireDig *string
	ConnectStartedAt, SendStartedAt, SendFinishedAt, ResponseAt  *time.Time
}

// values lists every field (nil when absent) in a fixed order, as comparable
// values.
func (o obs) values() []any {
	v := func(p any) any {
		switch x := p.(type) {
		case *netip.Addr:
			if x != nil {
				return *x
			}
		case *int32:
			if x != nil {
				return *x
			}
		case *int64:
			if x != nil {
				return *x
			}
		case *string:
			if x != nil {
				return *x
			}
		case *time.Time:
			if x != nil {
				return x.UTC().Truncate(time.Microsecond)
			}
		}
		return nil
	}
	return []any{v(o.LocalAddr), v(o.LocalPort), v(o.PeerAddr), v(o.PeerPort), v(o.NetnsInode), v(o.DialedAddr),
		v(o.PeerAddrKind), v(o.PodUID), v(o.ConnectStartedAt), v(o.SendStartedAt), v(o.SendFinishedAt), v(o.ResponseAt),
		v(o.ProviderRequestID), v(o.K8sAuditID), v(o.WireDig)}
}

func (o obs) equal(p obs) bool { return slices.Equal(o.values(), p.values()) }

// keeps reports whether p carries every field o has, with the same value: a
// later transition may add fields but never change or drop recorded ones.
func (o obs) keeps(p obs) bool {
	ov, pv := o.values(), p.values()
	for i := range ov {
		if ov[i] != nil && ov[i] != pv[i] {
			return false
		}
	}
	return true
}

// postClaim lists the allowed transitions after the permit claim (TASK-03
// 3.2 attempt outcome transitions). dispatched → failed is not allowed: failed means
// the request headers were never written. unknown → resolved happens only
// through resolve_unknown_attempt.
//
// SPEC-QUESTION: TASK-05 3.2 reports the outcome once, after the response, so
// claimed → response_received is allowed directly next to claimed →
// dispatched → response_received.
var postClaim = map[string][]string{
	"claimed":    {"dispatched", "response_received", "failed", "unknown"},
	"dispatched": {"response_received", "unknown"},
}

// checkObservation validates o for transition (TASK-05 3.4 AdapterObservation:
// the connection key local_addr, local_port, netns_inode is always present
// except for a failure before connect).
//
//   - dispatched: address tuple, netns_inode, dialed_addr, peer_addr_kind,
//     pod_uid, connect_started_at and send_started_at; no response_at.
//   - response_received: all of dispatched plus send_finished_at and
//     response_at.
//   - failed (before WroteHeaders): pod_uid; no send_started_at,
//     send_finished_at or response_at.
//   - unknown: pod_uid; no response_at. An adapter that restarts after the
//     claim reports unknown without knowing its socket (TASK-05 3.2 restart
//     reconciliation), so the rest may be absent.
//
// Addresses are plain IPs: an unspecified address (0.0.0.0, ::,
// ::ffff:0.0.0.0) is refused as it names no connection end, and an IPv6 zone
// is refused as TASK-10 correlation does not support it as a key. In every case
// local_addr, local_port and netns_inode come together,
// peer_addr and peer_port come together, peer_addr_kind needs peer_addr, and
// the timestamps that are present do not go backwards.
func checkObservation(attemptID, transition string, in Observation) (obs, bool) {
	var o obs
	if in.AttemptID != attemptID {
		return o, false
	}
	ok := true
	addr := func(s *string) *netip.Addr {
		if s == nil {
			return nil
		}
		// An unspecified address (0.0.0.0, ::, and the IPv4-mapped
		// ::ffff:0.0.0.0, which correlation does not filter) names no
		// connection end. A zoned address is not supported as a correlation
		// key: TASK-10 skips such a row. Both are refused here.
		a, err := netip.ParseAddr(*s)
		if err != nil || a.Zone() != "" || a.Unmap().IsUnspecified() {
			ok = false
			return nil
		}
		return &a
	}
	port := func(p *int64) *int32 {
		if p == nil {
			return nil
		}
		if *p < 1 || *p > 65535 {
			ok = false
			return nil
		}
		v := int32(*p)
		return &v
	}
	ts := func(s *string) *time.Time {
		if s == nil {
			return nil
		}
		t, err := time.Parse(time.RFC3339Nano, *s)
		if err != nil {
			ok = false
			return nil
		}
		t = t.UTC().Truncate(time.Microsecond)
		return &t
	}
	text := func(s *string, max int) *string {
		if s != nil && (*s == "" || len(*s) > max) {
			ok = false
		}
		return s
	}
	o.LocalAddr, o.PeerAddr, o.DialedAddr = addr(in.LocalAddr), addr(in.PeerAddr), addr(in.DialedAddr)
	o.LocalPort, o.PeerPort = port(in.LocalPort), port(in.PeerPort)
	if in.NetnsInode != nil && *in.NetnsInode <= 0 {
		ok = false
	}
	o.NetnsInode = in.NetnsInode
	if in.PeerAddrKind != nil && !slices.Contains([]string{"service_vip", "endpoint", "external"}, *in.PeerAddrKind) {
		ok = false
	}
	o.PeerAddrKind = in.PeerAddrKind
	if in.PodUID != nil && !isUUID(*in.PodUID) {
		ok = false
	}
	o.PodUID = in.PodUID
	if in.WireBodyDigest != nil && !isDigest(*in.WireBodyDigest) {
		ok = false
	}
	o.WireDig = in.WireBodyDigest
	o.ProviderRequestID, o.K8sAuditID = text(in.ProviderRequestID, 256), text(in.K8sAuditID, 256)
	o.ConnectStartedAt, o.SendStartedAt = ts(in.ConnectStartedAt), ts(in.SendStartedAt)
	o.SendFinishedAt, o.ResponseAt = ts(in.SendFinishedAt), ts(in.ResponseAt)
	if !ok {
		return o, false
	}

	all := func(ps ...bool) bool { return !slices.Contains(ps, false) }
	none := func(ps ...bool) bool { return !slices.Contains(ps, true) }
	conn := []bool{o.LocalAddr != nil, o.LocalPort != nil, o.NetnsInode != nil}
	peer := []bool{o.PeerAddr != nil, o.PeerPort != nil}
	if !(all(conn...) || none(conn...)) || !(all(peer...) || none(peer...)) || (o.PeerAddrKind != nil && o.PeerAddr == nil) {
		return o, false
	}
	var last *time.Time
	for _, t := range []*time.Time{o.ConnectStartedAt, o.SendStartedAt, o.SendFinishedAt, o.ResponseAt} {
		if t == nil {
			continue
		}
		if last != nil && t.Before(*last) {
			return o, false
		}
		last = t
	}
	sent := all(conn...) && all(peer...) && o.DialedAddr != nil && o.PeerAddrKind != nil && o.PodUID != nil &&
		o.ConnectStartedAt != nil && o.SendStartedAt != nil
	switch transition {
	case "dispatched":
		return o, sent && o.ResponseAt == nil
	case "response_received":
		return o, sent && o.SendFinishedAt != nil && o.ResponseAt != nil
	case "failed":
		// Before WroteHeaders nothing counts as sent: a send_started_at means
		// the request may have reached the target, which is unknown.
		return o, o.PodUID != nil && o.SendStartedAt == nil && o.SendFinishedAt == nil && o.ResponseAt == nil
	case "unknown":
		return o, o.PodUID != nil && o.ResponseAt == nil
	}
	return o, false
}

// reasonCodes is the COMMON reason code dictionary.
var reasonCodes = []string{
	"AUTH_REQUIRED", "CLAIM_CODE_INVALID", "SESSION_BINDING_INVALID", "ENDPOINT_NOT_REGISTERED", "SERVICE_SCOPE_DENIED",
	"TARGET_SCOPE_DENIED", "DISCLOSURE_SCOPE_DENIED", "CONTENT_PATTERN_DENIED", "DATA_CLASS_DENIED", "APPROVAL_REQUIRED",
	"INTENT_DIVERGENCE_ESCALATED", "INTENT_ACK_REQUIRED", "PERMISSION_WIDENING_ACK_REQUIRED", "LOCK_TIMEOUT",
	"APPROVAL_INVALID", "APPROVAL_UNAVAILABLE", "SESSION_BUDGET_EXHAUSTED", "CONTEXT_INCOMPLETE", "POLICY_UNAVAILABLE",
	"POLICY_VERSION_MISMATCH", "POLICY_EPOCH_STALE", "CATALOG_DIGEST_MISMATCH", "DECISION_EXPIRED", "HOLD_ACTIVE",
	"CONTROL_HEALTH_UNAVAILABLE", "POD_OBSERVATION_NOT_READY", "WORK_READINESS_EXPIRED", "WORK_READINESS_BINDING_MISMATCH",
	"CLIENT_KEY_BODY_CONFLICT", "PREFLIGHT_MISMATCH", "CONTENT_DIGEST_MISMATCH", "DESTINATION_NOT_ALLOWED",
	"TLS_VERIFY_FAILED", "CREDENTIAL_UNAVAILABLE", "PERMIT_INVALID", "RESPONSE_TOO_LARGE", "TARGET_REJECTED",
	"TARGET_UNAVAILABLE", "MODEL_BLOCKED", "TARGET_IDENTITY_CHANGED", "EVENT_ID_CONFLICT", "TARGET_KEY_BODY_CONFLICT",
	"TOOL_NOT_REGISTERED", "TOOL_BUDGET_EXHAUSTED", "MODEL_OUTPUT_TRUNCATED", "MODEL_SCHEMA_INVALID",
	"STARTUP_GUARD_UNAVAILABLE", "SCHEMA_INVALID", "ACTION_DIGEST_MISMATCH", "RESOURCE_NOT_FOUND",
	"STATE_STORE_UNAVAILABLE", "OUTCOME_TIMEOUT", "BODY_TOO_LARGE", "RATE_LIMITED",
}

// validOutcomeReasons: COMMON codes without duplicates; failed and unknown
// carry at least one. The adapter-specific mapping is TASK-05's table.
func validOutcomeReasons(transition string, codes []string) bool {
	if (transition == "failed" || transition == "unknown") && len(codes) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] || !slices.Contains(reasonCodes, c) {
			return false
		}
		seen[c] = true
	}
	return true
}

// Outcome applies a post-claim transition reported by the attempt's adapter
// and stores its AdapterObservation (COMMON API implementation contract: state CAS,
// store attempt_observations, then ack). The keys are read without locks, then
// reservations → attempts are locked in the global order and checked again.
// Reporting the current state again with the same reason codes and
// observation returns the stored result; anything else that is not an
// allowed transition is 409 PERMIT_INVALID.
//
// SPEC-QUESTION: COMMON registers dispatch_started, response_received,
// attempt_failed and attempt_uncertain with producer TASK-05, and TASK-05 3.4
// has the adapter emit them; their payloads need status_code and stage, which
// the outcome body does not carry. The coordinator therefore appends no
// event for these transitions, although the COMMON API table mentions an
// audit COMMIT.
func (s *Service) Outcome(ctx context.Context, a Adapter, attemptID string, transition string, in Observation, reasons []string) (*ReleaseResult, error) {
	if reasons == nil {
		reasons = []string{}
	}
	if !isUUID(attemptID) || !validOutcomeReasons(transition, reasons) {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "malformed outcome")
	}
	o, ok := checkObservation(attemptID, transition, in)
	if !ok {
		return nil, fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "observation does not fit the transition")
	}
	var resID, adapterID string
	err := s.Pool.QueryRow(ctx, `SELECT reservation_id::text, adapter_id FROM coordinator.attempts WHERE attempt_id = $1`,
		attemptID).Scan(&resID, &adapterID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && adapterID != a.AdapterID) {
		return nil, fail(http.StatusNotFound, "RESOURCE_NOT_FOUND", "no such attempt for this adapter")
	}
	if err != nil {
		return nil, err
	}

	var out *ReleaseResult
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM coordinator.reservations WHERE reservation_id = $1 FOR UPDATE`, resID); err != nil {
			return err
		}
		var state string
		var stored []string
		if err := tx.QueryRow(ctx, `SELECT state, reason_codes FROM coordinator.attempts WHERE attempt_id = $1 FOR UPDATE`,
			attemptID).Scan(&state, &stored); err != nil {
			return err
		}
		prev, have, err := loadObservation(ctx, tx, attemptID)
		if err != nil {
			return err
		}
		if state == transition {
			if have && prev.equal(o) && slices.Equal(stored, reasons) {
				out = &ReleaseResult{AttemptID: attemptID, State: state, ReasonCodes: stored}
				return nil
			}
			return conflict("PERMIT_INVALID", "attempt is already "+state+" with another report")
		}
		if !slices.Contains(postClaim[state], transition) {
			return conflict("PERMIT_INVALID", "attempt is "+state+"; "+transition+" is not allowed")
		}
		if have && !prev.keeps(o) {
			return conflict("PERMIT_INVALID", "observation changes fields recorded at an earlier transition")
		}
		if _, err := tx.Exec(ctx, `UPDATE coordinator.attempts SET state = $2, reason_codes = $3, updated_at = statement_timestamp()
WHERE attempt_id = $1`, attemptID, transition, reasons); err != nil {
			return err
		}
		if err := storeObservation(ctx, tx, attemptID, o); err != nil {
			return err
		}
		out = &ReleaseResult{AttemptID: attemptID, State: transition, ReasonCodes: reasons}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func addrText(a *netip.Addr) *string {
	if a == nil {
		return nil
	}
	s := a.String()
	return &s
}

// storeObservation writes the attempt's one attempt_observations row; a
// later transition replaces it with the superset checked by keeps.
func storeObservation(ctx context.Context, tx pgx.Tx, attemptID string, o obs) error {
	_, err := tx.Exec(ctx, `
INSERT INTO coordinator.attempt_observations (attempt_id, local_addr, local_port, peer_addr, peer_port, netns_inode,
    dialed_addr, peer_addr_kind, pod_uid, connect_started_at, send_started_at, send_finished_at, response_at,
    provider_request_id, k8s_audit_id, wire_body_digest, recorded_at)
VALUES ($1, $2::inet, $3, $4::inet, $5, $6, $7::inet, $8, $9::uuid, $10, $11, $12, $13, $14, $15, $16, statement_timestamp())
ON CONFLICT (attempt_id) DO UPDATE SET
    local_addr = EXCLUDED.local_addr, local_port = EXCLUDED.local_port, peer_addr = EXCLUDED.peer_addr,
    peer_port = EXCLUDED.peer_port, netns_inode = EXCLUDED.netns_inode, dialed_addr = EXCLUDED.dialed_addr,
    peer_addr_kind = EXCLUDED.peer_addr_kind, pod_uid = EXCLUDED.pod_uid,
    connect_started_at = EXCLUDED.connect_started_at, send_started_at = EXCLUDED.send_started_at,
    send_finished_at = EXCLUDED.send_finished_at, response_at = EXCLUDED.response_at,
    provider_request_id = EXCLUDED.provider_request_id, k8s_audit_id = EXCLUDED.k8s_audit_id,
    wire_body_digest = EXCLUDED.wire_body_digest, recorded_at = EXCLUDED.recorded_at`,
		attemptID, addrText(o.LocalAddr), o.LocalPort, addrText(o.PeerAddr), o.PeerPort, o.NetnsInode,
		addrText(o.DialedAddr), o.PeerAddrKind, o.PodUID, o.ConnectStartedAt, o.SendStartedAt, o.SendFinishedAt, o.ResponseAt,
		o.ProviderRequestID, o.K8sAuditID, o.WireDig)
	return err
}

// loadObservation reads the attempt's stored observation, if any.
func loadObservation(ctx context.Context, tx pgx.Tx, attemptID string) (obs, bool, error) {
	var o obs
	var local, peer, dialed *string
	err := tx.QueryRow(ctx, `
SELECT host(local_addr), local_port, host(peer_addr), peer_port, netns_inode, host(dialed_addr), peer_addr_kind,
       pod_uid::text, connect_started_at, send_started_at, send_finished_at, response_at,
       provider_request_id, k8s_audit_id, wire_body_digest
FROM coordinator.attempt_observations WHERE attempt_id = $1`, attemptID).Scan(
		&local, &o.LocalPort, &peer, &o.PeerPort, &o.NetnsInode, &dialed, &o.PeerAddrKind,
		&o.PodUID, &o.ConnectStartedAt, &o.SendStartedAt, &o.SendFinishedAt, &o.ResponseAt,
		&o.ProviderRequestID, &o.K8sAuditID, &o.WireDig)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, false, nil
	}
	if err != nil {
		return o, false, err
	}
	for _, p := range []struct {
		s   *string
		dst **netip.Addr
	}{{local, &o.LocalAddr}, {peer, &o.PeerAddr}, {dialed, &o.DialedAddr}} {
		if p.s == nil {
			continue
		}
		a, err := netip.ParseAddr(*p.s)
		if err != nil {
			return o, false, err
		}
		*p.dst = &a
	}
	return o, true, nil
}
