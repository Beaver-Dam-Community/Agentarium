package receiver

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStore is the PostgreSQL Store. Writer runs as receiver_writer
// (SELECT, INSERT) and Reader as receipt_reader (SELECT), so the receipt path
// cannot write (TASK-08 3.1 "separate the receiver INSERT role from the collector SELECT role").
// Build both pools with NewRolePool.
type PGStore struct {
	Writer *pgxpool.Pool
	Reader *pgxpool.Pool
}

// Database roles of the two PGStore pools (TASK-08 3.1 GRANTs).
const (
	RoleWriter = "receiver_writer"
	RoleReader = "receipt_reader"
)

// NewRolePool opens a pool whose every connection runs as role (SET ROLE in
// AfterConnect), so a login that is a member of both receiver_writer and
// receipt_reader still uses one role's grants per pool. It queries once and
// checks current_user, so a missing role or membership stops the receiver
// at start instead of at the first request.
func NewRolePool(ctx context.Context, dbURL, role string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, err
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	var current string
	if err := pool.QueryRow(ctx, "SELECT current_user").Scan(&current); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect as %s: %w", role, err)
	}
	if current != role {
		pool.Close()
		return nil, fmt.Errorf("pool runs as %q, want %q", current, role)
	}
	return pool, nil
}

const insertAttempt = `
INSERT INTO receiver.receiver_attempts
    (client_attempt_id, action_key, client_principal, wire_body_digest, body_bytes, outcome, effect_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING receipt_attempt_id::text`

const insertEffect = `
INSERT INTO receiver.receiver_effects
    (action_key, receiver_mode, wire_body_digest, content_digest_server, body_bytes, client_principal)
VALUES ($1, $2, $3, $4, $5, $6)`

// Submit implements Store. The effect row and its attempt commit together, so
// a restart never leaves one without the other (TASK-08 3 item 3).
func (s *PGStore) Submit(ctx context.Context, sub Submission) (SubmitResult, error) {
	switch sub.Mode {
	case ModeNonIdempotent:
		return s.submitNew(ctx, sub)
	case ModeIdempotent:
		if sub.ActionKey == nil {
			return SubmitResult{}, errors.New("idempotent submission without action_key")
		}
		return s.submitIdempotent(ctx, sub)
	}
	return SubmitResult{}, fmt.Errorf("unknown receiver_mode %q", sub.Mode)
}

// submitNew records a new effect for every submission (non_idempotent mode).
func (s *PGStore) submitNew(ctx context.Context, sub Submission) (SubmitResult, error) {
	var res SubmitResult
	err := pgx.BeginFunc(ctx, s.Writer, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, insertEffect+` RETURNING effect_id::text`,
			sub.ActionKey, string(sub.Mode), sub.WireBodyDigest, sub.ContentDigestServer, sub.BodyBytes, sub.ClientPrincipal,
		).Scan(&res.EffectID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, insertAttempt,
			sub.ClientAttemptID, sub.ActionKey, sub.ClientPrincipal, sub.WireBodyDigest, sub.BodyBytes, OutcomeEffectCreated, res.EffectID,
		).Scan(&res.ReceiptAttemptID)
	})
	if err != nil {
		return SubmitResult{}, err
	}
	res.Outcome = OutcomeEffectCreated
	res.ActionKey = sub.ActionKey
	res.WireBodyDigest = sub.WireBodyDigest
	res.BodyBytes = sub.BodyBytes
	return res, nil
}

// errConflict ends the effect transaction with a rollback when the existing
// effect of the key has a different digest.
var errConflict = errors.New("key body conflict")

// submitIdempotent handles the action_key unique conflict inside the effect
// transaction. A concurrent insert of the same key waits on the partial
// unique index; after it commits, DO NOTHING applies and the following
// SELECT (a new READ COMMITTED snapshot) sees the committed effect.
func (s *PGStore) submitIdempotent(ctx context.Context, sub Submission) (SubmitResult, error) {
	res := SubmitResult{ActionKey: sub.ActionKey}
	err := pgx.BeginFunc(ctx, s.Writer, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, insertEffect+`
ON CONFLICT (action_key) WHERE receiver_mode = 'idempotent' DO NOTHING
RETURNING effect_id::text`,
			sub.ActionKey, string(sub.Mode), sub.WireBodyDigest, sub.ContentDigestServer, sub.BodyBytes, sub.ClientPrincipal,
		).Scan(&res.EffectID)
		switch {
		case err == nil:
			res.Outcome = OutcomeEffectCreated
			res.WireBodyDigest = sub.WireBodyDigest
			res.BodyBytes = sub.BodyBytes
		case errors.Is(err, pgx.ErrNoRows):
			if err := tx.QueryRow(ctx, `
SELECT effect_id::text, wire_body_digest, body_bytes
FROM receiver.receiver_effects
WHERE action_key = $1 AND receiver_mode = 'idempotent'`, sub.ActionKey,
			).Scan(&res.EffectID, &res.WireBodyDigest, &res.BodyBytes); err != nil {
				return err
			}
			if res.WireBodyDigest != sub.WireBodyDigest {
				return errConflict
			}
			res.Outcome = OutcomeDuplicateReturned
		default:
			return err
		}
		return tx.QueryRow(ctx, insertAttempt,
			sub.ClientAttemptID, sub.ActionKey, sub.ClientPrincipal, sub.WireBodyDigest, sub.BodyBytes, res.Outcome, res.EffectID,
		).Scan(&res.ReceiptAttemptID)
	})
	if errors.Is(err, errConflict) {
		// The conflict attempt is written in its own transaction so the
		// rollback above cannot take it away (TASK-08 3 item 3). It refers to
		// no effect: the submission neither created nor returned one.
		var id string
		if err := s.Writer.QueryRow(ctx, insertAttempt,
			sub.ClientAttemptID, sub.ActionKey, sub.ClientPrincipal, sub.WireBodyDigest, sub.BodyBytes, OutcomeKeyBodyConflict, nil,
		).Scan(&id); err != nil {
			return SubmitResult{}, err
		}
		return SubmitResult{Outcome: OutcomeKeyBodyConflict, ReceiptAttemptID: id, ActionKey: sub.ActionKey}, nil
	}
	if err != nil {
		return SubmitResult{}, err
	}
	return res, nil
}

// RecordKeyMissing implements Store.
func (s *PGStore) RecordKeyMissing(ctx context.Context, sub Submission) (string, error) {
	var id string
	err := s.Writer.QueryRow(ctx, insertAttempt,
		sub.ClientAttemptID, nil, sub.ClientPrincipal, sub.WireBodyDigest, sub.BodyBytes, OutcomeKeyMissingRejected, nil,
	).Scan(&id)
	return id, err
}

// Receipt implements Store. Effects and attempts are read in one
// REPEATABLE READ snapshot so effect_count and the attempt list agree.
func (s *PGStore) Receipt(ctx context.Context, actionKey string) (ReceiptRecords, error) {
	var out ReceiptRecords
	err := pgx.BeginTxFunc(ctx, s.Reader, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT effect_id::text, wire_body_digest, content_digest_server, body_bytes, committed_at
FROM receiver.receiver_effects
WHERE action_key = $1
ORDER BY committed_at, effect_id`, actionKey)
		if err != nil {
			return err
		}
		out.Effects, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReceiptEffect, error) {
			var e ReceiptEffect
			err := r.Scan(&e.EffectID, &e.WireBodyDigest, &e.ContentDigestServer, &e.BodyBytes, &e.CommittedAt)
			return e, err
		})
		if err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `
SELECT receipt_attempt_id::text, client_attempt_id::text, received_at, wire_body_digest, outcome
FROM receiver.receiver_attempts
WHERE action_key = $1
ORDER BY received_at, receipt_attempt_id`, actionKey)
		if err != nil {
			return err
		}
		out.Attempts, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReceiptAttempt, error) {
			var a ReceiptAttempt
			err := r.Scan(&a.ReceiptAttemptID, &a.ClientAttemptID, &a.ReceivedAt, &a.WireBodyDigest, &a.Outcome)
			return a, err
		})
		return err
	})
	return out, err
}
