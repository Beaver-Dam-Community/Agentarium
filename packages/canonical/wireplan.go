package canonical

import (
	"errors"
	"time"
)

// WirePlan is the immutable adapter request plan (COMMON WirePlan). Authorization
// and other credential headers are never part of SafeHeaders or WireBodyDigest.
type WirePlan struct {
	Method          string            `json:"method"`
	OriginID        string            `json:"origin_id"`
	Route           string            `json:"route"`
	SafeHeaders     map[string]string `json:"safe_headers"`
	BodyBytes       []byte            `json:"body_bytes"`
	WireBodyDigest  string            `json:"wire_body_digest"`
	ResponseLimit   int64             `json:"response_limit"`
	Timeout         time.Duration     `json:"timeout"`
	ExpectedTLSName string            `json:"expected_tls_name"`
	// ExpectedURISAN is the target's expected_uri_san (ca_ref
	// agentarium-trust only, empty otherwise). The transport checks the
	// server certificate's single URI SAN against it; ExpectedTLSName is then
	// SNI only (COMMON WirePlan expected_uri_san?, TASK-05 3.2). It is not
	// part of wire_body_digest.
	ExpectedURISAN string   `json:"expected_uri_san,omitempty"`
	AllowedCIDRs   []string `json:"allowed_cidrs"`
}

// Preparer is the Prepare interface (TASK-02 4). Implementations (service
// mappers, TASK-05) must not use the network or secrets and must return the
// same WireBodyDigest for the same inputs. R is the adapter's resolved-reference type.
type Preparer[R any] interface {
	Prepare(envelope ActionEnvelope, content Content, resolved R) (WirePlan, error)
}

// VerifyContent checks that content belongs to the envelope and that
// SHA-256(content_bytes) equals the envelope content_digest.
func VerifyContent(env ActionEnvelope, c Content) error {
	if env.ContentDigest == nil {
		if c.ContentDigest != "" || len(c.ContentBytes) != 0 {
			return errors.New("envelope has no content but content was supplied")
		}
		return nil
	}
	if c.ContentDigest != *env.ContentDigest || SHA256Hex(c.ContentBytes) != *env.ContentDigest {
		return errors.New("content digest does not match envelope content_digest")
	}
	if c.ActionID != env.ActionID || c.Tenant != env.Tenant {
		return errors.New("content does not belong to the envelope action")
	}
	return nil
}

// ReceiverWireBody returns the receiver.submit request body, JCS(payload),
// which is exactly the stored content bytes, after verifying them.
func ReceiverWireBody(env ActionEnvelope, c Content) ([]byte, error) {
	if env.OperationID != OpReceiverSubmit {
		return nil, errors.New("not a receiver.submit envelope")
	}
	if env.ContentDigest == nil {
		return nil, errors.New("receiver.submit envelope has no content_digest")
	}
	if err := VerifyContent(env, c); err != nil {
		return nil, err
	}
	return append([]byte(nil), c.ContentBytes...), nil
}
