package export

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ManifestLeaseTTL is fixed by audit.acquire_manifest_lease (TASK-07 3.2.1).
const ManifestLeaseTTL = 30 * time.Second

var ErrLeaseHeld = errors.New("manifest lease held by another exporter")
var ErrLeaseLost = errors.New("manifest lease lost or fencing token stale")

type heldLease struct {
	token    int64
	deadline time.Time
}

// PGLease is the PostgreSQL manifest writer lease. Holder must be unique per
// process: replicas sharing a holder string would share one fencing token, so
// cmd/exporter always appends a fresh UUID to its configured instance ID. The local deadline is
// measured from before the acquire call, so it never outlives the DB lease
// under a monotonic clock. The DB trigger is the authoritative fence: every
// intent and manifest INSERT must carry the current token of a live lease.
type PGLease struct {
	Pool   *pgxpool.Pool
	Holder string
	// Margin stops new durable steps this long before the local deadline.
	Margin time.Duration
	// OnNewToken runs after this holder obtains a token it did not hold
	// before (first acquisition or takeover), outside the lease mutex.
	OnNewToken func(chain string, token int64)
	mu         sync.Mutex
	held       map[string]heldLease
}

func (l *PGLease) margin() time.Duration {
	if l.Margin <= 0 {
		return 5 * time.Second
	}
	return l.Margin
}

// Acquire takes or renews the chain lease and returns its fencing token.
func (l *PGLease) Acquire(ctx context.Context, chain string) (int64, error) {
	if l.Pool == nil || l.Holder == "" || (chain != "gcs" && chain != "gcs_decision_inputs") {
		return 0, errors.New("invalid manifest lease configuration")
	}
	start := time.Now()
	rows, err := auditdb.New(l.Pool).AcquireManifestLease(ctx, auditdb.AcquireManifestLeaseParams{ChainID: chain, Holder: l.Holder})
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held == nil {
		l.held = map[string]heldLease{}
	}
	if err != nil || len(rows) != 1 || rows[0].FencingToken < 1 {
		delete(l.held, chain)
		if err == nil {
			err = ErrLeaseHeld
		}
		return 0, err
	}
	previous, had := l.held[chain]
	token := rows[0].FencingToken
	l.held[chain] = heldLease{token: token, deadline: start.Add(ManifestLeaseTTL)}
	if (!had || previous.token != token) && l.OnNewToken != nil {
		hook := l.OnNewToken
		defer func() { go hook(chain, token) }()
	}
	return token, nil
}

// Check returns the held token while enough lease time remains.
func (l *PGLease) Check(_ context.Context, chain string) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	h, ok := l.held[chain]
	if !ok || !time.Now().Add(l.margin()).Before(h.deadline) {
		return 0, ErrLeaseLost
	}
	return h.token, nil
}

// Release expires a held lease early, e.g. on shutdown.
func (l *PGLease) Release(ctx context.Context, chain string) error {
	l.mu.Lock()
	h, ok := l.held[chain]
	delete(l.held, chain)
	l.mu.Unlock()
	if !ok {
		return nil
	}
	_, err := auditdb.New(l.Pool).ReleaseManifestLease(ctx, auditdb.ReleaseManifestLeaseParams{ChainID: chain, Holder: l.Holder, FencingToken: h.token})
	return err
}

// ErrRenewInterval rejects intervals at or above TTL minus the safety margin,
// which would make Check fail between renewals.
var ErrRenewInterval = errors.New("lease renewal interval must be below TTL minus margin")

// Run renews the given chains every interval until ctx ends, then releases.
func (l *PGLease) Run(ctx context.Context, chains []string, every time.Duration, onError func(string, error)) error {
	if every <= 0 || every >= ManifestLeaseTTL-l.margin() {
		return ErrRenewInterval
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		for _, chain := range chains {
			call, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := l.Acquire(call, chain)
			cancel()
			if err != nil && ctx.Err() == nil && onError != nil {
				onError(chain, err)
			}
		}
		select {
		case <-ctx.Done():
			for _, chain := range chains {
				done, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = l.Release(done, chain)
				cancel()
			}
			return nil
		case <-tick.C:
		}
	}
}

// fencingRejected reports the trigger's stale-token rejection.
func fencingRejected(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "AU401"
}
