package store

import (
	"context"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/store/healthdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// All health paths require one authoritative current boot. Timestamps cannot
// resolve conflicting non-retired rows; return an error before reporting or
// changing health state. No rows retains the existing bootstrap/absent behavior.
func currentNode(ctx context.Context, q *healthdb.Queries, node pgtype.UUID) (healthdb.HealthNodeBootGeneration, error) {
	rows, err := q.CurrentNodes(ctx, node)
	if err != nil {
		return healthdb.HealthNodeBootGeneration{}, err
	}
	switch len(rows) {
	case 0:
		return healthdb.HealthNodeBootGeneration{}, pgx.ErrNoRows
	case 1:
		return rows[0], nil
	default:
		return healthdb.HealthNodeBootGeneration{}, pgx.ErrTooManyRows
	}
}
