package sessions

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// PGActivePolicy reads release.active_policy (TASK-14, migration
// 20261018092000_release_active_policy) with one plain SELECT; identity_app
// has SELECT only.
type PGActivePolicy struct{}

var _ ActivePolicyReader = PGActivePolicy{}

// ErrNoActivePolicy means the environment has no active_policy row yet.
var ErrNoActivePolicy = errors.New("sessions: no active_policy row")

func (PGActivePolicy) ActivePolicy(ctx context.Context, q Querier, environment string) (ActiveBundle, error) {
	var a ActiveBundle
	err := q.QueryRow(ctx, `
SELECT scope_id, bundle_id, artifact_digest, expected_opa_revision, epoch
FROM release.active_policy WHERE scope_id = $1`, environment).
		Scan(&a.ScopeID, &a.BundleID, &a.ArtifactDigest, &a.ExpectedOPARevision, &a.Epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return ActiveBundle{}, ErrNoActivePolicy
	}
	return a, err
}
