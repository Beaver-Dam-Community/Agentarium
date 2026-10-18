// Package feed reads TASK-08's existing cross-service views. It neither advances
// a durable cursor nor implies that timestamp order is database commit order.
package feed

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/feed/feeddb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxPageSize is a local bounded-query safeguard, not a new shared API limit.
const MaxPageSize = 100

type Reader struct {
	queries *feeddb.Queries
	tenant  string
}

func New(pool *pgxpool.Pool, tenant string) (*Reader, error) {
	if pool == nil || tenant == "" || !utf8.ValidString(tenant) {
		return nil, errors.New("collector feed requires a pool and trusted tenant")
	}
	return &Reader{queries: feeddb.New(pool), tenant: tenant}, nil
}

type Cursor struct {
	ReceivedAt time.Time
	EventID    uuid.UUID
}
type Event struct {
	EventID                uuid.UUID
	EventType, Tenant      string
	ActionID, AttemptID    *uuid.UUID
	SourceTime, ReceivedAt time.Time
	SafePayload            json.RawMessage
}
type Target struct {
	ActionID            uuid.UUID
	Tenant, OperationID string
	CanonicalTarget     json.RawMessage
}

// Page follows the existing (received_at,event_id) strict cursor ordering, with
// tenant filtering in SQL before LIMIT. Nil after starts at the earliest row.
// A transaction can commit later with an earlier received_at; Page does not
// provide lossless streaming/checkpoint semantics for that case.
func (r *Reader) Page(ctx context.Context, after *Cursor, limit int) ([]Event, error) {
	if r == nil || r.queries == nil || limit < 1 || limit > MaxPageSize {
		return nil, errors.New("invalid collector page query")
	}
	arg := feeddb.ReadPageParams{Tenant: r.tenant, PageLimit: int32(limit)}
	if after != nil {
		if after.ReceivedAt.IsZero() {
			return nil, errors.New("incomplete collector cursor")
		}
		arg.AfterTime = pgtype.Timestamptz{Time: after.ReceivedAt, Valid: true}
		arg.AfterID = pgtype.UUID{Bytes: after.EventID, Valid: true}
	}
	rows, err := r.queries.ReadPage(ctx, arg)
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(rows))
	for _, row := range rows {
		out = append(out, Event{EventID: uuid.UUID(row.EventID.Bytes), EventType: row.EventType, Tenant: row.Tenant, ActionID: optionalID(row.ActionID), AttemptID: optionalID(row.AttemptID), SourceTime: row.SourceTime.Time.UTC(), ReceivedAt: row.ReceivedAt.Time.UTC(), SafePayload: row.SafePayload})
	}
	return out, nil
}

// Target returns pgx.ErrNoRows for another tenant's action exactly as for an
// unknown action. It never falls back to decisions.actions or adapter APIs.
func (r *Reader) Target(ctx context.Context, actionID uuid.UUID) (Target, error) {
	if r == nil || r.queries == nil {
		return Target{}, errors.New("uninitialized collector reader")
	}
	row, err := r.queries.ReadTarget(ctx, feeddb.ReadTargetParams{Tenant: r.tenant, ActionID: pgtype.UUID{Bytes: actionID, Valid: true}})
	if err != nil {
		return Target{}, err
	}
	return Target{ActionID: uuid.UUID(row.ActionID.Bytes), Tenant: row.Tenant, OperationID: row.OperationID, CanonicalTarget: row.CanonicalTarget}, nil
}
func optionalID(v pgtype.UUID) *uuid.UUID {
	if !v.Valid {
		return nil
	}
	id := uuid.UUID(v.Bytes)
	return &id
}

// WithTx returns a reader that queries inside tx, so the collector reads the
// feed and writes its own state in one transaction.
func (r *Reader) WithTx(tx pgx.Tx) *Reader {
	return &Reader{queries: r.queries.WithTx(tx), tenant: r.tenant}
}

// MaxActionEvents bounds one action's feed history read (local safeguard).
const MaxActionEvents = 256

// ActionEvents returns this tenant's collector_feed rows of one action in
// (received_at,event_id) order. More than MaxActionEvents rows is an error
// rather than a truncated history.
func (r *Reader) ActionEvents(ctx context.Context, actionID uuid.UUID) ([]Event, error) {
	if r == nil || r.queries == nil {
		return nil, errors.New("uninitialized collector reader")
	}
	rows, err := r.queries.ReadActionEvents(ctx, feeddb.ReadActionEventsParams{Tenant: r.tenant, ActionID: pgtype.UUID{Bytes: actionID, Valid: true}, PageLimit: MaxActionEvents + 1})
	if err != nil {
		return nil, err
	}
	if len(rows) > MaxActionEvents {
		return nil, errors.New("collector feed action history exceeds the local bound")
	}
	out := make([]Event, 0, len(rows))
	for _, row := range rows {
		id := actionID
		out = append(out, Event{EventID: uuid.UUID(row.EventID.Bytes), EventType: row.EventType, Tenant: r.tenant, ActionID: &id, AttemptID: optionalID(row.AttemptID), ReceivedAt: row.ReceivedAt.Time.UTC(), SafePayload: row.SafePayload})
	}
	return out, nil
}
