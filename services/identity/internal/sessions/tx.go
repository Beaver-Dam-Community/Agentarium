package sessions

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func (s *Service) inTx(ctx context.Context, opts pgx.TxOptions, fn func(pgx.Tx) error) error {
	return InTx(ctx, s.Pool, opts, fn)
}

// LockTimeout is the per-transaction lock wait (TASK-03 3.2 lock order).
const LockTimeout = "2s"

// InTx runs fn in a transaction that waits at most LockTimeout for any row
// lock. A lock wait past it rolls the whole transaction back and returns 503
// LOCK_TIMEOUT.
func InTx(ctx context.Context, pool *pgxpool.Pool, opts pgx.TxOptions, fn func(pgx.Tx) error) error {
	err := pgx.BeginTxFunc(ctx, pool, opts, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '"+LockTimeout+"'"); err != nil {
			return err
		}
		operationErr := fn(tx)
		var conflict *auditConflict
		if errors.As(operationErr, &conflict) {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			if rollbackErr := tx.Rollback(cleanup); rollbackErr != nil {
				return rollbackErr
			}
		}
		return operationErr
	})
	var conflict *auditConflict
	if errors.As(err, &conflict) {
		// BeginTxFunc has ended the business transaction before this separate
		// autocommit. A cancelled HTTP request must not silently erase an incident.
		incident, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if _, recordErr := pool.Exec(incident,
			"SELECT audit.audit_record_conflict('audit_event', $1, $2, $3)",
			conflict.eventID, conflict.digest, conflict.sourceID); recordErr != nil {
			return recordErr
		}
		return fail(http.StatusConflict, "EVENT_ID_CONFLICT", "audit event ID conflict")
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" { // lock_not_available
		return fail(http.StatusServiceUnavailable, "LOCK_TIMEOUT", "row lock wait exceeded "+LockTimeout)
	}
	return err
}
