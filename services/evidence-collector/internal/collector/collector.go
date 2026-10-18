// Package collector is the TASK-08 3.2 collection loop. It follows
// audit.collector_feed with a durable cursor, schedules receipt polls for
// receiver.submit actions, classifies receipts (R1-R6) and stores each
// changed judgment as an evidence.destination_observations revision together
// with its destination_observed audit event in one transaction.
package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/feed"
	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/receipt"
	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/store/storedb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// FeedName is the collector_cursors key (TASK-08 3.2 DDL comment).
	FeedName = "audit.collector_feed"
	// ReceiverOperation is the catalog operation served by the test receiver.
	ReceiverOperation = "receiver.submit"
	// ObservationDeadline is the TASK-08 3.2 30-second action deadline.
	ObservationDeadline = 30 * time.Second
	// PollInterval is the TASK-08 3.2 1-second feed polling interval.
	PollInterval = time.Second
	// LatePollInterval is the last backoff step, kept after the deadline.
	LatePollInterval = 8 * time.Second
)

// Backoff is the TASK-08 3.2 receipt schedule: immediately, then 1, 2, 4, 8s.
var Backoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}

// Receipts is the receipt client (internal/receipt.Client).
type Receipts interface {
	Check(context.Context, receipt.Expected) (receipt.Result, error)
}

// Config is trusted installation configuration.
type Config struct {
	Tenant string
	Audit  AuditConfig
	// Settle keeps the cursor this far behind DB time. received_at is not a
	// commit-order watermark (feed README): an append that commits late can
	// carry an earlier received_at. Events newer than now-Settle are left for
	// the next pass; reprocessing is idempotent.
	Settle time.Duration
	// LateWindow bounds polling after the deadline for a late receipt; after
	// it no further revision is produced unless a new feed event re-opens it.
	LateWindow time.Duration
	PageSize   int
}

// Collector runs the loop. One replica per tenant (the epoch lock is
// exclusive); polls are claimed with SKIP LOCKED regardless.
type Collector struct {
	Pool     *pgxpool.Pool
	Feed     *feed.Reader
	Receipts Receipts
	Cfg      Config
	Log      *slog.Logger
	NewID    func() string

	lastOK atomic.Int64 // unix nanos of the last pass without error
}

func (c *Collector) validate() error {
	if c == nil || c.Pool == nil || c.Feed == nil || c.Receipts == nil || c.Cfg.Tenant == "" {
		return errors.New("collector: incomplete configuration")
	}
	if c.Cfg.Settle < 0 || c.Cfg.LateWindow < 0 || c.Cfg.PageSize < 1 || c.Cfg.PageSize > feed.MaxPageSize {
		return errors.New("collector: invalid timing or page size")
	}
	return c.Cfg.Audit.validate()
}

func (c *Collector) newID() string {
	if c.NewID != nil {
		return c.NewID()
	}
	return uuid.NewString()
}

func (c *Collector) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

// LastSuccess is the time of the last loop pass that completed without error.
func (c *Collector) LastSuccess() time.Time {
	n := c.lastOK.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// Run ingests and polls every PollInterval until ctx ends.
func (c *Collector) Run(ctx context.Context) error {
	if err := c.validate(); err != nil {
		return err
	}
	t := time.NewTicker(PollInterval)
	defer t.Stop()
	for {
		if err := c.Pass(ctx); err != nil && ctx.Err() == nil {
			c.log().Error("evidence collection pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Pass ingests available feed pages, then works through due polls.
func (c *Collector) Pass(ctx context.Context) error {
	if err := c.validate(); err != nil {
		return err
	}
	for i := 0; i < 10; i++ {
		more, err := c.Ingest(ctx)
		if err != nil {
			return err
		}
		if !more {
			break
		}
	}
	for i := 0; i < 50; i++ {
		did, err := c.PollOnce(ctx)
		if err != nil {
			return err
		}
		if !did {
			break
		}
	}
	c.lastOK.Store(time.Now().UnixNano())
	return nil
}

// Ingest processes one feed page after the durable cursor and advances the
// cursor in the same transaction. more reports a full page.
func (c *Collector) Ingest(ctx context.Context) (more bool, err error) {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	q := storedb.New(tx)
	f := c.Feed.WithTx(tx)
	now, err := clock(ctx, q)
	if err != nil {
		return false, err
	}
	var after *feed.Cursor
	cur, err := q.LockCursor(ctx, FeedName)
	switch {
	case err == nil:
		after = &feed.Cursor{ReceivedAt: cur.LastReceivedAt.Time, EventID: uuid.UUID(cur.LastEventID.Bytes)}
	case !errors.Is(err, pgx.ErrNoRows):
		return false, err
	}
	events, err := f.Page(ctx, after, c.Cfg.PageSize)
	if err != nil {
		return false, err
	}
	var last *feed.Event
	settled := true
	for i := range events {
		ev := &events[i]
		if ev.ReceivedAt.After(now.Add(-c.Cfg.Settle)) {
			settled = false
			break
		}
		if err := c.handle(ctx, tx, q, f, ev, now); err != nil {
			return false, fmt.Errorf("feed event %s: %w", ev.EventID, err)
		}
		last = ev
	}
	if last != nil {
		if err := q.SaveCursor(ctx, storedb.SaveCursorParams{Feed: FeedName,
			LastReceivedAt: pgtype.Timestamptz{Time: last.ReceivedAt, Valid: true},
			LastEventID:    pgtype.UUID{Bytes: last.EventID, Valid: true}}); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return settled && len(events) == c.Cfg.PageSize, nil
}

// handle applies the TASK-08 3.2 triggers of one feed event.
func (c *Collector) handle(ctx context.Context, tx pgx.Tx, q *storedb.Queries, f *feed.Reader, ev *feed.Event, now time.Time) error {
	switch ev.EventType {
	case "response_received", "attempt_uncertain", "attempt_failed":
	default:
		return nil // preflight_passed and dispatch_started are read at poll time
	}
	if ev.ActionID == nil {
		return nil
	}
	target, err := f.Target(ctx, *ev.ActionID)
	if errors.Is(err, pgx.ErrNoRows) {
		// No gateway action for this tenant: nothing is inferred.
		c.log().Error("collector feed action has no actions_target_view row; no evidence recorded", "action_id", ev.ActionID.String(), "event_id", ev.EventID.String())
		return nil
	}
	if err != nil {
		return err
	}
	if target.OperationID == ReceiverOperation {
		return q.SchedulePoll(ctx, storedb.SchedulePollParams{
			ActionID:   pgtype.UUID{Bytes: *ev.ActionID, Valid: true},
			Now:        pgtype.Timestamptz{Time: now, Valid: true},
			DeadlineAt: pgtype.Timestamptz{Time: now.Add(ObservationDeadline), Valid: true},
		})
	}
	if ev.EventType != "response_received" {
		return nil
	}
	// R4: a k8s or model call; the upper bound is accepted.
	_, err = c.record(ctx, tx, q, *ev.ActionID, ev.AttemptID, notReceiverPayload(ev.ActionID.String()), now)
	return err
}

// PollOnce claims one due receipt poll, queries the receipt and stores a
// changed judgment. It reports whether a poll was due.
func (c *Collector) PollOnce(ctx context.Context) (bool, error) {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	q := storedb.New(tx)
	f := c.Feed.WithTx(tx)
	now, err := clock(ctx, q)
	if err != nil {
		return false, err
	}
	p, err := q.NextDuePoll(ctx, pgtype.Timestamptz{Time: now, Valid: true})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, tx.Commit(ctx)
	}
	if err != nil {
		return false, err
	}
	actionID := uuid.UUID(p.ActionID.Bytes)
	want, attemptID, ctxErr := c.expected(ctx, f, actionID)
	var res receipt.Result
	rerr := ctxErr
	if rerr == nil {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		res, rerr = c.Receipts.Check(rctx, want)
		cancel()
	}
	if rerr != nil {
		c.log().Warn("receipt not available", "action_id", actionID.String(), "err", rerr)
	}
	// Re-read DB time: the receipt call may have taken seconds.
	if now, err = clock(ctx, q); err != nil {
		return false, err
	}
	deadline := p.DeadlineAt.Time
	var next *time.Time
	// recordJudgment builds the payload and stores it. A failure here is
	// specific to this action's receipt data (an unclassifiable receipt, a
	// SCHEMA_INVALID audit append, or an event-ID conflict), not an
	// infrastructure fault, so it must not roll back and leave this poll due
	// forever and starve every other action. judgmentErr carries such a
	// failure out so the poll is deferred instead (review #227).
	var judgmentErr error
	recordJudgment := func(res receipt.Result) {
		pl, perr := receiptPayload(actionID.String(), res)
		if perr != nil {
			judgmentErr = perr
			return
		}
		if _, perr := c.record(ctx, tx, q, actionID, attemptID, pl, now); perr != nil {
			judgmentErr = perr
		}
	}
	switch {
	case rerr == nil && res.RuleID != "R5":
		// R1, R2, R3 or R6: a final judgment from a valid receipt.
		recordJudgment(res)
	case now.Before(deadline):
		step := Backoff[min(int(p.Polls), len(Backoff)-1)]
		at := now.Add(step)
		if at.After(deadline) {
			at = deadline
		}
		next = &at
	default:
		// Deadline reached without a final judgment: R5 unknown.
		if rerr == nil {
			recordJudgment(res)
		} else {
			pl := unavailablePayload(actionID.String())
			if _, perr := c.record(ctx, tx, q, actionID, attemptID, pl, now); perr != nil {
				judgmentErr = perr
			}
		}
		if judgmentErr == nil && now.Before(p.FirstSeenAt.Time.Add(c.Cfg.LateWindow)) {
			at := now.Add(LatePollInterval)
			next = &at
		}
	}
	// Isolate a per-action judgment failure only when it is a data problem
	// that would recur on every retry (an unclassifiable receipt, a
	// SCHEMA_INVALID audit append, or an event-ID conflict): roll back and, in
	// a separate transaction, push next_poll_at back so one bad receipt does
	// not block the rest or spin at 1s. A transient fault (a 42501 source not
	// yet granted, a connection error) is returned instead, so the poll stays
	// due and retries as soon as the fault clears (review #227).
	if judgmentErr != nil {
		if !isPollDataError(judgmentErr) {
			return false, judgmentErr
		}
		_ = tx.Rollback(ctx)
		c.log().Warn("receipt judgment failed; deferring poll", "action_id", actionID.String(), "err", judgmentErr)
		return true, c.deferPoll(ctx, p.ActionID, p.Polls, p.DeadlineAt.Time)
	}
	np := pgtype.Timestamptz{}
	if next != nil {
		np = pgtype.Timestamptz{Time: *next, Valid: true}
	}
	if err := q.UpdatePoll(ctx, storedb.UpdatePollParams{NextPollAt: np, ActionID: p.ActionID}); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// isPollDataError reports whether a judgment failure is a data problem that
// would recur on every retry: an unclassifiable receipt (receiptPayload), an
// event-ID conflict (ErrAuditConflict), or a SCHEMA_INVALID audit append
// (SQLSTATE 22023). These are deferred so one bad action does not block the
// rest. A transient fault (e.g. 42501 source not allowed) is not a data error:
// it is returned so the poll stays due and retries once the fault clears.
func isPollDataError(err error) bool {
	if errors.Is(err, ErrAuditConflict) {
		return true
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code == "22023" // SCHEMA_INVALID
	}
	// receiptPayload returns a plain error (no SQLSTATE) for a receipt that
	// matches no destination_observed situation row.
	return !isPgError(err)
}

// isPgError reports whether err carries a PostgreSQL SQLSTATE.
func isPgError(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe)
}

// deferPoll pushes one poll's next_poll_at back by a backoff step (capped at
// the deadline) in its own transaction, used to isolate a poll whose judgment
// failed so it does not block or spin. It never records a judgment.
func (c *Collector) deferPoll(ctx context.Context, actionID pgtype.UUID, polls int32, deadline time.Time) error {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	q := storedb.New(tx)
	now, err := clock(ctx, q)
	if err != nil {
		return err
	}
	step := Backoff[min(int(polls), len(Backoff)-1)]
	at := now.Add(step)
	if !deadline.IsZero() && at.After(deadline) {
		// Past the deadline, retry on the late-poll cadence so a persistently
		// bad receipt is reconsidered but never spins.
		at = now.Add(LatePollInterval)
	}
	if err := q.UpdatePoll(ctx, storedb.UpdatePollParams{NextPollAt: pgtype.Timestamptz{Time: at, Valid: true}, ActionID: actionID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// expected builds the trusted comparison context from the defined views
// only: the latest preflight_passed wire_body_digest, canonical_target
// target_id/route_id and whether attempt_failed was seen.
func (c *Collector) expected(ctx context.Context, f *feed.Reader, actionID uuid.UUID) (receipt.Expected, *uuid.UUID, error) {
	events, err := f.ActionEvents(ctx, actionID)
	if err != nil {
		return receipt.Expected{}, nil, err
	}
	want := receipt.Expected{ActionID: actionID.String()}
	var attemptID *uuid.UUID
	for _, ev := range events {
		if ev.AttemptID != nil {
			attemptID = ev.AttemptID
		}
		switch ev.EventType {
		case "preflight_passed":
			var pl struct {
				WireBodyDigest string `json:"wire_body_digest"`
			}
			if err := json.Unmarshal(ev.SafePayload, &pl); err != nil {
				return receipt.Expected{}, attemptID, err
			}
			want.WireBodyDigest = pl.WireBodyDigest
		case "attempt_failed":
			want.AttemptFailed = true
		}
	}
	if want.WireBodyDigest == "" {
		return receipt.Expected{}, attemptID, errors.New("no preflight_passed wire_body_digest for the action")
	}
	target, err := f.Target(ctx, actionID)
	if err != nil {
		return receipt.Expected{}, attemptID, err
	}
	var ct struct {
		TargetID string `json:"target_id"`
		RouteID  string `json:"route_id"`
	}
	if err := json.Unmarshal(target.CanonicalTarget, &ct); err != nil || ct.TargetID == "" || ct.RouteID == "" {
		return receipt.Expected{}, attemptID, errors.New("canonical_target lacks target_id/route_id")
	}
	want.TargetID, want.RouteID = ct.TargetID, ct.RouteID
	return want, attemptID, nil
}

// record appends a revision only when the judgment (rule_id, evidence_level)
// differs from the latest revision, so a re-read event or a retried pass
// never duplicates a revision. The observation row and its audit event share
// tx; any failure rolls both back.
func (c *Collector) record(ctx context.Context, tx pgx.Tx, q *storedb.Queries, actionID uuid.UUID, attemptID *uuid.UUID, p Payload, now time.Time) (bool, error) {
	revision := int32(1)
	latest, err := q.LatestObservation(ctx, pgtype.UUID{Bytes: actionID, Valid: true})
	switch {
	case err == nil:
		if latest.RuleID == p.RuleID && latest.EvidenceLevel == p.EvidenceLevel {
			return false, nil
		}
		revision = latest.Revision + 1
	case !errors.Is(err, pgx.ErrNoRows):
		return false, err
	}
	eventID := c.newID()
	var attempt *string
	aid := pgtype.UUID{}
	if attemptID != nil {
		s := attemptID.String()
		attempt = &s
		aid = pgtype.UUID{Bytes: *attemptID, Valid: true}
	}
	var eid pgtype.UUID
	if err := eid.Scan(eventID); err != nil {
		return false, err
	}
	row := storedb.InsertObservationParams{ActionID: pgtype.UUID{Bytes: actionID, Valid: true}, Revision: revision,
		AttemptID: aid, Tenant: c.Cfg.Tenant, EvidenceLevel: p.EvidenceLevel, RuleID: p.RuleID,
		SourceTime: pgtype.Timestamptz{Time: now, Valid: true}, EventID: eid}
	if p.ReceiptDigest != nil {
		row.ReceiptDigest = pgtype.Text{String: *p.ReceiptDigest, Valid: true}
	}
	if p.EffectCount != nil {
		row.EffectCount = pgtype.Int4{Int32: int32(*p.EffectCount), Valid: true}
	}
	if err := q.InsertObservation(ctx, row); err != nil {
		return false, err
	}
	if err := appendDestinationObserved(ctx, tx, c.Cfg.Audit, c.Cfg.Tenant, eventID, actionID.String(), attempt, now, p); err != nil {
		return false, err
	}
	c.log().Info("destination observed", "action_id", actionID.String(), "revision", revision, "rule_id", p.RuleID, "evidence_level", p.EvidenceLevel)
	return true, nil
}

func clock(ctx context.Context, q *storedb.Queries) (time.Time, error) {
	t, err := q.Clock(ctx)
	if err != nil {
		return time.Time{}, err
	}
	return t.Time.UTC(), nil
}
