// Package prepare holds the pure per-service WirePlan mappers of TASK-05
// (3.1, chapter 6 packages/adapters/prepare). A mapper uses no network and no
// secret: it rebuilds the request only from the stored envelope, the stored
// content and the catalog of the loaded bundle, and reports every field that
// disagrees.
//
// Only receiver.submit is implemented here (M2-7). kubernetes-reader, model
// and evidence-reader mappers are later milestones.
package prepare

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/internal/strictjson"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Reason codes (COMMON reason code dictionary).
const (
	ReasonPreflightMismatch     = "PREFLIGHT_MISMATCH"
	ReasonContentDigestMismatch = "CONTENT_DIGEST_MISMATCH"
	ReasonCatalogDigestMismatch = "CATALOG_DIGEST_MISMATCH"
)

// Receiver constants (TASK-05 3.1 receiver-sender row, COMMON implementation initial values).
const (
	ReceiverAdapterID   = "receiver-sender"
	ReceiverMaxBody     = 64 << 10
	ExternalTimeout     = 10 * time.Second
	IdempotencyHeader   = "Idempotency-Key"
	UserAgent           = "agentarium-adapter/receiver-sender"
	receiverContentType = "application/json"
)

// Mismatch is one preflight disagreement. Field is the compared field name
// that goes into preflight_rejected.compared_fields.
type Mismatch struct {
	ReasonCode string
	Field      string
	Detail     string
}

func (m *Mismatch) Error() string { return m.ReasonCode + " " + m.Field + ": " + m.Detail }

func mismatch(code, field, format string, a ...any) *Mismatch {
	return &Mismatch{ReasonCode: code, Field: field, Detail: fmt.Sprintf(format, a...)}
}

// ReceiverPlan builds the receiver.submit WirePlan from the stored envelope and
// content and the loaded catalog (TASK-05 3.1). The body is JCS(payload), the
// stored content bytes, after SHA-256(content) == envelope content_digest is
// verified. X-Agentarium-Attempt-Id is not in the plan: the attempt does not
// exist before the reservation, and the transport binds it at send time.
//
// SPEC-QUESTION: COMMON WirePlan lists X-Agentarium-Attempt-Id among
// safe_headers, but Prepare runs before the reservation that creates the
// attempt. The header is bound to the request after the reservation and is
// not part of wire_body_digest either way.
func ReceiverPlan(env canonical.ActionEnvelope, content canonical.Content, cat canonical.Catalog) (canonical.WirePlan, canonical.CatalogOperation, canonical.CatalogTarget, *Mismatch) {
	var zero canonical.WirePlan
	if env.OperationID != canonical.OpReceiverSubmit {
		return zero, canonical.CatalogOperation{}, canonical.CatalogTarget{}, mismatch(ReasonPreflightMismatch, "operation_id", "%q is not receiver.submit", env.OperationID)
	}
	if env.CatalogDigest != cat.CatalogDigest {
		return zero, canonical.CatalogOperation{}, canonical.CatalogTarget{}, mismatch(ReasonCatalogDigestMismatch, "catalog_digest", "envelope catalog_digest differs from the loaded catalog")
	}
	op, ok := cat.Operations[env.OperationID]
	if !ok {
		return zero, op, canonical.CatalogTarget{}, mismatch(ReasonPreflightMismatch, "operation_id", "receiver.submit is not in the loaded catalog")
	}
	tg, ok := cat.Targets[env.CanonicalTarget.TargetID]
	if !ok || !slices.Contains(tg.OperationIDs, op.OperationID) {
		return zero, op, tg, mismatch(ReasonPreflightMismatch, "canonical_target.target_id", "target %q is not registered for receiver.submit", env.CanonicalTarget.TargetID)
	}
	if m := checkReceiverEnvelope(env, op, tg); m != nil {
		return zero, op, tg, m
	}

	// Content: digest, ownership, and the bytes are the JCS payload.
	body, err := canonical.ReceiverWireBody(env, content)
	if err != nil {
		return zero, op, tg, mismatch(ReasonContentDigestMismatch, "content_digest", "%v", err)
	}
	var payload canonical.ReceiverPayload
	if err := strictjson.Decode(body, &payload); err != nil {
		return zero, op, tg, mismatch(ReasonPreflightMismatch, "content", "stored content is not a receiver payload: %v", err)
	}
	jcs, err := canonical.CanonicalJSON(payload)
	if err != nil || string(jcs) != string(body) {
		return zero, op, tg, mismatch(ReasonPreflightMismatch, "content", "stored content is not JCS(payload)")
	}
	// Disclosure: the envelope fields must be exactly the fields the payload
	// discloses (summary, plus email when it is not null).
	want := []string{"summary"}
	if payload.Email != nil {
		want = append(want, "email")
	}
	slices.Sort(want)
	if !slices.Equal(want, env.DisclosureFields) {
		return zero, op, tg, mismatch(ReasonPreflightMismatch, "disclosure_fields", "envelope %v, payload discloses %v", env.DisclosureFields, want)
	}
	// The same deterministic content checker the gateway ran (TASK-02 3.3).
	if nerr := canonical.CheckReceiverContent(op, payload); nerr != nil {
		return zero, op, tg, mismatch(ReasonPreflightMismatch, "content", "content checker: %v", nerr.ReasonCodes)
	}
	if len(body) > ReceiverMaxBody {
		return zero, op, tg, mismatch(ReasonPreflightMismatch, "bytes", "body is %d bytes, limit %d", len(body), ReceiverMaxBody)
	}
	if env.Bytes != int64(len(body)) {
		return zero, op, tg, mismatch(ReasonPreflightMismatch, "bytes", "envelope bytes %d, body %d", env.Bytes, len(body))
	}

	if err := checkOrigin(tg); err != nil {
		return zero, op, tg, mismatch(ReasonPreflightMismatch, "origin", "%v", err)
	}
	plan := canonical.WirePlan{
		Method:   op.Method,
		OriginID: tg.Origin,
		Route:    op.RouteTemplate,
		SafeHeaders: map[string]string{
			IdempotencyHeader: env.ActionID,
			"User-Agent":      UserAgent,
			"Content-Type":    receiverContentType,
		},
		BodyBytes:       body,
		WireBodyDigest:  canonical.WireBodyDigest(body),
		ResponseLimit:   op.ResponseLimitBytes,
		Timeout:         ExternalTimeout,
		ExpectedTLSName: tg.ExpectedTLSName,
		AllowedCIDRs:    append([]string(nil), tg.AllowedCIDRs...),
	}
	if tg.ExpectedURISAN != nil {
		plan.ExpectedURISAN = *tg.ExpectedURISAN
	}
	return plan, op, tg, nil
}

func checkReceiverEnvelope(env canonical.ActionEnvelope, op canonical.CatalogOperation, tg canonical.CatalogTarget) *Mismatch {
	switch {
	case op.AdapterID != ReceiverAdapterID:
		return mismatch(ReasonPreflightMismatch, "adapter_id", "catalog routes receiver.submit to %q", op.AdapterID)
	case op.Method != "POST" || op.Transport != "https_rest":
		return mismatch(ReasonPreflightMismatch, "method", "catalog method %s/%s", op.Method, op.Transport)
	case strings.Contains(op.RouteTemplate, "{"):
		return mismatch(ReasonPreflightMismatch, "route", "receiver route %q has parameters", op.RouteTemplate)
	case env.CanonicalTarget.RouteID != op.RouteID:
		return mismatch(ReasonPreflightMismatch, "canonical_target.route_id", "envelope %q, catalog %q", env.CanonicalTarget.RouteID, op.RouteID)
	case env.CanonicalTarget != (canonical.CanonicalTarget{TargetID: tg.TargetID, RouteID: op.RouteID}):
		return mismatch(ReasonPreflightMismatch, "canonical_target", "receiver target carries operation-specific fields")
	case env.EndpointID != op.EndpointID || tg.EndpointID != op.EndpointID:
		return mismatch(ReasonPreflightMismatch, "endpoint_id", "envelope %q, operation %q, target %q", env.EndpointID, op.EndpointID, tg.EndpointID)
	case len(env.Limits) != 0:
		return mismatch(ReasonPreflightMismatch, "limits", "receiver.submit has no limits")
	case env.SchemaVersion != op.SchemaVersion:
		return mismatch(ReasonPreflightMismatch, "schema_version", "envelope %q, catalog %q", env.SchemaVersion, op.SchemaVersion)
	case env.CanonicalizationVersion != canonical.CanonicalizationVersion:
		return mismatch(ReasonPreflightMismatch, "canonicalization_version", "envelope %q, adapter %q", env.CanonicalizationVersion, canonical.CanonicalizationVersion)
	case op.ResponseLimitBytes <= 0:
		return mismatch(ReasonPreflightMismatch, "response_limit", "catalog response_limit_bytes %d", op.ResponseLimitBytes)
	}
	return nil
}

func checkOrigin(tg canonical.CatalogTarget) error {
	u, err := url.Parse(tg.Origin)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return fmt.Errorf("origin %q is not https://host[:port]", tg.Origin)
	}
	if tg.ExpectedTLSName == "" {
		return errors.New("target has no expected_tls_name")
	}
	return nil
}

// ReceiverPolicy is the part of the loaded bundle data that bounds a
// receiver.submit request beyond the catalog: data.receiver
// .allowed_disclosure_fields (second defense, TASK-05 3.1) and
// data.adapter_constraints["receiver-sender"] (COMMON appendix A).
type ReceiverPolicy struct {
	AllowedDisclosureFields []string
	MaxRequestBytes         int64
	MaxResponseBytes        int64
	AllowedRouteIDs         []string
}

// CheckReceiverPolicy applies the bundle policy to a plan built by
// ReceiverPlan and returns the plan with response_limit lowered to the
// adapter constraint when that is smaller.
func CheckReceiverPolicy(plan canonical.WirePlan, env canonical.ActionEnvelope, op canonical.CatalogOperation, pol ReceiverPolicy) (canonical.WirePlan, *Mismatch) {
	for _, f := range env.DisclosureFields {
		if !slices.Contains(pol.AllowedDisclosureFields, f) {
			return plan, mismatch(ReasonPreflightMismatch, "disclosure_fields", "%q is not in data.receiver.allowed_disclosure_fields", f)
		}
	}
	if !slices.Contains(pol.AllowedRouteIDs, op.RouteID) {
		return plan, mismatch(ReasonPreflightMismatch, "route", "route %q is not in adapter_constraints.allowed_route_ids", op.RouteID)
	}
	if pol.MaxRequestBytes <= 0 || int64(len(plan.BodyBytes)) > pol.MaxRequestBytes {
		return plan, mismatch(ReasonPreflightMismatch, "bytes", "body %d bytes, adapter_constraints.max_request_bytes %d", len(plan.BodyBytes), pol.MaxRequestBytes)
	}
	if pol.MaxResponseBytes <= 0 {
		return plan, mismatch(ReasonPreflightMismatch, "response_limit", "adapter_constraints.max_response_bytes %d", pol.MaxResponseBytes)
	}
	if pol.MaxResponseBytes < plan.ResponseLimit {
		plan.ResponseLimit = pol.MaxResponseBytes
	}
	return plan, nil
}
