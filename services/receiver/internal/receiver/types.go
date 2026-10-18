// Package receiver is the TASK-08 3.1 test receiver: it computes the byte
// count and SHA-256 of what it actually received, records every receive
// attempt and the effects it created, and serves receipts to the evidence
// collector only.
package receiver

import (
	"context"
	"fmt"
	"time"
)

// Mode is receiver_mode. It is fixed per deployment by the environment lock
// and never read from a request (TASK-08 2).
type Mode string

const (
	ModeIdempotent    Mode = "idempotent"
	ModeNonIdempotent Mode = "non_idempotent"
)

// ParseMode accepts the two receiver_mode values only.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeIdempotent, ModeNonIdempotent:
		return Mode(s), nil
	}
	return "", fmt.Errorf("receiver_mode must be %q or %q, got %q", ModeIdempotent, ModeNonIdempotent, s)
}

// receiver_attempts.outcome values (TASK-08 3.1 DDL).
const (
	OutcomeEffectCreated      = "effect_created"
	OutcomeDuplicateReturned  = "duplicate_returned"
	OutcomeKeyBodyConflict    = "key_body_conflict"
	OutcomeKeyMissingRejected = "key_missing_rejected"
)

// Reason codes used by the receiver (COMMON reason code dictionary).
const (
	ReasonAuthRequired          = "AUTH_REQUIRED"
	ReasonSchemaInvalid         = "SCHEMA_INVALID"
	ReasonBodyTooLarge          = "BODY_TOO_LARGE"
	ReasonTargetKeyBodyConflict = "TARGET_KEY_BODY_CONFLICT"
	ReasonResourceNotFound      = "RESOURCE_NOT_FOUND"
	ReasonStateStoreUnavailable = "STATE_STORE_UNAVAILABLE"
	// ReasonReceiverKeyInvalid is the #169 proposal (401), not yet in COMMON.
	ReasonReceiverKeyInvalid = "RECEIVER_KEY_INVALID"
)

// Submission is one received POST /test/v1/submissions request. Every value
// here is computed by the receiver or taken from the verified connection;
// nothing is a client claim except the two header UUIDs.
type Submission struct {
	Mode                Mode
	ActionKey           *string // Idempotency-Key, canonical lower-case UUID
	ClientAttemptID     *string // X-Agentarium-Attempt-Id, canonical lower-case UUID
	ClientPrincipal     string  // verified client certificate URI SAN
	WireBodyDigest      string  // SHA-256 of the received bytes
	ContentDigestServer *string // canonical digest of the payload (not an independent source)
	BodyBytes           int
}

// SubmitResult reports what Submit recorded. For OutcomeEffectCreated and
// OutcomeDuplicateReturned the effect fields describe the (existing) effect;
// for OutcomeKeyBodyConflict only ReceiptAttemptID is set.
type SubmitResult struct {
	Outcome          string
	ReceiptAttemptID string
	EffectID         string
	ActionKey        *string
	WireBodyDigest   string
	BodyBytes        int
}

// ReceiptEffect is one receiver_effects row as the receipt shows it.
type ReceiptEffect struct {
	EffectID            string
	WireBodyDigest      string
	ContentDigestServer *string
	BodyBytes           int
	CommittedAt         time.Time
}

// ReceiptAttempt is one receiver_attempts row as the receipt shows it.
type ReceiptAttempt struct {
	ReceiptAttemptID string
	ClientAttemptID  *string
	ReceivedAt       time.Time
	WireBodyDigest   string
	Outcome          string
}

// ReceiptRecords are the rows of one action_key, read in one snapshot.
type ReceiptRecords struct {
	Effects  []ReceiptEffect
	Attempts []ReceiptAttempt
}

// Store records submissions and reads receipts. The PostgreSQL
// implementation is PGStore.
type Store interface {
	// Submit records the attempt and, when the mode allows it, the effect.
	// In idempotent mode a key_body_conflict attempt is written in its own
	// transaction after the effect transaction is rolled back.
	Submit(ctx context.Context, s Submission) (SubmitResult, error)
	// RecordKeyMissing writes a key_missing_rejected attempt and returns its ID.
	RecordKeyMissing(ctx context.Context, s Submission) (string, error)
	// Receipt reads the effects and attempts of one action_key.
	Receipt(ctx context.Context, actionKey string) (ReceiptRecords, error)
}
