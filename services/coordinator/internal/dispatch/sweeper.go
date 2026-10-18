package dispatch

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// SweepResult counts one sweep.
type SweepResult struct {
	Candidates int
	Released   int // case 1: expired unclaimed permits
	Uncertain  int // case 2: no outcome 60 s after the claim
	Failed     int
}

// Sweep runs both TASK-03 3.2 sweeper cases, at most SweepBatch candidates in
// total per run: (1) planned attempts whose permit expired unclaimed are
// released with their budget restored; (2) claimed or dispatched attempts
// with no outcome OutcomeTimeout after the claim become unknown
// (OUTCOME_TIMEOUT, attempt_uncertain), with no budget restore and no hold.
// The candidates are read without locks; each one is handled in its own
// transaction in the global lock order, so one failure does not stop the
// others.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	var r SweepResult
	expired, err := s.candidates(ctx, SweepBatch, `
SELECT p.attempt_id::text
FROM coordinator.dispatch_permits p
JOIN coordinator.attempts t ON t.attempt_id = p.attempt_id
WHERE p.claimed_at IS NULL AND p.expires_at <= statement_timestamp() AND t.state = 'planned'
ORDER BY p.expires_at
LIMIT $1`)
	if err != nil {
		return r, err
	}
	silent, err := s.candidates(ctx, SweepBatch-len(expired), `
SELECT attempt_id::text FROM coordinator.attempts
WHERE state IN ('claimed', 'dispatched') AND claimed_at <= statement_timestamp() - make_interval(secs => $2)
ORDER BY claimed_at
LIMIT $1`, OutcomeTimeout.Seconds())
	if err != nil {
		return r, err
	}
	r.Candidates = len(expired) + len(silent)
	for _, id := range expired {
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		_, err := s.release(ctx, id, BySweeper, []string{"PERMIT_INVALID"}, nil)
		var e *Error
		switch {
		case err == nil:
			r.Released++
		case errors.Is(err, errNotExpired), errors.As(err, &e) && e.Code == "PERMIT_INVALID":
			// Claimed or renewed since the candidate read: nothing to do.
		default:
			r.Failed++
			s.log().Error("sweeper release failed", "attempt_id", id, "err", err)
		}
	}
	for _, id := range silent {
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		done, err := s.timeOut(ctx, id)
		switch {
		case err != nil:
			r.Failed++
			s.log().Error("sweeper outcome timeout failed", "attempt_id", id, "err", err)
		case done:
			r.Uncertain++
		}
	}
	return r, nil
}

// candidates reads up to limit attempt IDs; sql takes the limit as $1.
func (s *Service) candidates(ctx context.Context, limit int, sql string, args ...any) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.Pool.Query(ctx, sql, append([]any{limit}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// timeOut turns a claimed or dispatched attempt without an outcome into
// unknown (sweeper case 2). It locks reservations → attempts and checks the
// state and claim age again; false means an outcome arrived in between.
func (s *Service) timeOut(ctx context.Context, attemptID string) (bool, error) {
	var resID string
	err := s.Pool.QueryRow(ctx, `SELECT reservation_id::text FROM coordinator.attempts WHERE attempt_id = $1`, attemptID).Scan(&resID)
	if err != nil {
		return false, err
	}
	done := false
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM coordinator.reservations WHERE reservation_id = $1 FOR UPDATE`, resID); err != nil {
			return err
		}
		var due bool
		err := tx.QueryRow(ctx, `
SELECT state IN ('claimed', 'dispatched') AND claimed_at <= statement_timestamp() - make_interval(secs => $2)
FROM coordinator.attempts WHERE attempt_id = $1 FOR UPDATE`, attemptID, OutcomeTimeout.Seconds()).Scan(&due)
		if err != nil || !due {
			return err
		}
		reasons := []string{"OUTCOME_TIMEOUT"}
		if _, err := tx.Exec(ctx, `UPDATE coordinator.attempts SET state = 'unknown', reason_codes = $2, updated_at = statement_timestamp()
WHERE attempt_id = $1`, attemptID, reasons); err != nil {
			return err
		}
		if err := s.audit().Append(ctx, tx, Event{Type: "attempt_uncertain", Payload: map[string]any{
			"attempt_id": attemptID, "stage": "outcome_timeout", "reason_codes": reasons,
		}}); err != nil {
			return depErr(err, "STATE_STORE_UNAVAILABLE", "audit_append")
		}
		done = true
		return nil
	})
	return done, err
}

// RunSweeper sweeps at once and then every SweepInterval until ctx ends,
// reporting the coordinator lease on the same cycle. Errors are logged and
// the loop goes on; a lease that cannot be reported lets it expire, which
// TASK-10 turns into a hold.
func (s *Service) RunSweeper(ctx context.Context) {
	t := time.NewTicker(SweepInterval)
	defer t.Stop()
	for {
		if r, err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
			s.log().Error("sweep failed", "err", err)
		} else if r.Released > 0 || r.Uncertain > 0 || r.Failed > 0 {
			s.log().Info("sweep", "candidates", r.Candidates, "released", r.Released, "uncertain", r.Uncertain, "failed", r.Failed)
		}
		leases := s.Leases
		if leases == nil {
			leases = Unwired{}
		}
		if err := leases.Report(ctx); err != nil && ctx.Err() == nil {
			s.log().Error("coordinator lease report failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
