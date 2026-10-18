package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

// Snapshots returns the currently loaded bundle snapshot, or nil before the
// first load. *policyloader.Loader implements it.
type Snapshots interface {
	Current() *policyloader.Snapshot
}

// Service holds the gateway's store, the bundle loader and the dependencies.
// Nil dependencies are treated as Unwired.
type Service struct {
	Pool   *pgxpool.Pool
	Bundle Snapshots
	// Environment is the installation's environment (ActionEnvelope
	// environment, TASK-04 chapter 2 install settings).
	Environment string
	// GatewayIdentity is the gateway's own SAN, stored as
	// decisions.authenticated_gateway.
	GatewayIdentity string
	// ModelProfiles is the install config of model.generate profile
	// constants (canonical.LoadModelProfiles, --model-profiles). It is
	// immutable after startup; catalog() attaches a copy to every catalog it
	// takes from a bundle snapshot. Nil leaves every model.generate
	// unregistered (403 ENDPOINT_NOT_REGISTERED).
	ModelProfiles map[string]canonical.ModelProfileConfig

	Policy    PolicySource
	Health    ControlHealth
	Readiness Readiness
	Adapters  AdapterState
	Audit     Auditor
	Probes    Probes
	Intent    IntentChecker

	// Adapter maps adapter_id to the adapter's base URL and the mTLS client
	// that accepts only that adapter's service certificate (NewAdapterClient).
	// An adapter_id it does not know fails the delivery.
	Adapter func(adapterID string) (AdapterEndpoint, bool)

	Log *slog.Logger

	// beforeReevaluateStore, when set by a test, runs after a :reevaluate
	// evaluation and before its decision transaction, to reproduce races
	// between the pre-check and the store.
	beforeReevaluateStore func(actionID string)

	kickOnce sync.Once
	kick     chan struct{}
}

// catalog decodes snap's data.catalog and attaches a copy of the installed
// model profile constants, which bundle data.catalog does not carry. Every
// path that uses the bundle catalog goes through it.
func (s *Service) catalog(snap *policyloader.Snapshot) (canonical.Catalog, error) {
	cat, err := snap.Catalog()
	if err != nil {
		return canonical.Catalog{}, err
	}
	cat.ModelProfiles = canonical.CloneModelProfiles(s.ModelProfiles)
	return cat, nil
}

func (s *Service) policy() PolicySource {
	if s.Policy == nil {
		return Unwired{}
	}
	return s.Policy
}

func (s *Service) health() ControlHealth {
	if s.Health == nil {
		return Unwired{}
	}
	return s.Health
}

func (s *Service) readiness() Readiness {
	if s.Readiness == nil {
		return Unwired{}
	}
	return s.Readiness
}

func (s *Service) adapters() AdapterState {
	if s.Adapters == nil {
		return Unwired{}
	}
	return s.Adapters
}

func (s *Service) audit() Auditor {
	if s.Audit == nil {
		return Unwired{}
	}
	return s.Audit
}

func (s *Service) probes() Probes {
	if s.Probes == nil {
		return Unwired{}
	}
	return s.Probes
}

func (s *Service) intent() IntentChecker {
	if s.Intent == nil {
		return UnwiredIntent{}
	}
	return s.Intent
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// snapshot returns the bundle snapshot one request uses from start to end
// (COMMON policy decision contract 6). Without one the gateway answers 503
// POLICY_UNAVAILABLE.
func (s *Service) snapshot() (*policyloader.Snapshot, error) {
	if s.Bundle == nil {
		return nil, unavailable("POLICY_UNAVAILABLE", "no bundle loader")
	}
	snap := s.Bundle.Current()
	if snap == nil || snap.Prepared() == nil {
		return nil, unavailable("POLICY_UNAVAILABLE", "no bundle loaded")
	}
	return snap, nil
}

// inTx runs fn in a READ COMMITTED write transaction that waits at most
// LockTimeout for a row lock (COMMON lock order and timestamps). A longer wait is 503
// LOCK_TIMEOUT; any other failure that is not an *Error is 503
// STATE_STORE_UNAVAILABLE. Nothing is committed on error.
func (s *Service) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '"+LockTimeout+"'"); err != nil {
			return err
		}
		return fn(tx)
	})
	return mapStoreErr(err)
}

// readTx runs fn in one REPEATABLE READ READ ONLY transaction, the snapshot
// all facts of one evaluation come from (TASK-04 chapter 3 step 4).
func (s *Service) readTx(ctx context.Context, fn func(pgx.Tx) error) error {
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, fn)
	return mapStoreErr(err)
}

func mapStoreErr(err error) error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, errExistingAction) || errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" { // lock_not_available
		return unavailable("LOCK_TIMEOUT", "row lock wait exceeded "+LockTimeout)
	}
	return &Error{Status: http.StatusServiceUnavailable, Code: "STATE_STORE_UNAVAILABLE", Msg: err.Error()}
}

func (s *Service) kickCh() chan struct{} {
	s.kickOnce.Do(func() { s.kick = make(chan struct{}, 1) })
	return s.kick
}

// Kick wakes the execute worker after an allow decision is committed.
func (s *Service) Kick() {
	select {
	case s.kickCh() <- struct{}{}:
	default:
	}
}
