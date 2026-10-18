package dispatch

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// PGPolicy locks this environment's release.active_policy row FOR SHARE
// through release.lock_active_policy (migration
// 20261018092000_release_active_policy): FOR SHARE needs UPDATE privilege,
// which coordinator_app does not get on active_policy.
type PGPolicy struct{ Environment string }

var _ PolicySource = PGPolicy{}

func (p PGPolicy) LockActivePolicy(ctx context.Context, tx pgx.Tx) (ActivePolicy, error) {
	if p.Environment == "" {
		return ActivePolicy{}, ErrUnwired
	}
	var a ActivePolicy
	err := tx.QueryRow(ctx, `SELECT epoch, catalog_digest, expected_opa_revision FROM release.lock_active_policy($1)`,
		p.Environment).Scan(&a.Epoch, &a.CatalogDigest, &a.ExpectedOPARevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return ActivePolicy{}, unavailable("POLICY_UNAVAILABLE", "no active_policy row for "+p.Environment)
	}
	return a, err
}
