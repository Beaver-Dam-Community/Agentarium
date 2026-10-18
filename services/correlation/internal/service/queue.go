package service

import (
	"context"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Input identifies immutable stored evidence, independent of its source clock.
type Input struct {
	Kind string
	ID   uuid.UUID
}
type Evaluation struct {
	Node     uuid.UUID
	From, To time.Time
	Inputs   []Input
}
type Queue interface {
	Pending(context.Context, time.Time) ([]Evaluation, error)
	Complete(context.Context, Evaluation) error
}

// PoolQueue removes exact input IDs only after successful evaluation.
// This also finds transactions that commit after a scan with an older
// received_at. INSERT triggers persist pending work with the source transaction.
// Completed history does not participate in scheduling queries.
// Node pagination and a per-node batch limit keep a failed node from starving
// other nodes. Each evaluation spans at most one minute plus the join overlap.
type PoolQueue struct {
	Pool  *pgxpool.Pool
	after uuid.UUID
}

const queueNodes = 64
const queueInputs = 128

func (q *PoolQueue) Pending(ctx context.Context, now time.Time) ([]Evaluation, error) {
	cutoff := now.Add(-worker.MinDelay)
	rows, err := q.Pool.Query(ctx, `WITH nodes AS (
  SELECT DISTINCT node_uid FROM correlation.pending_inputs
  WHERE node_uid > $1 AND source_time < $2 ORDER BY node_uid LIMIT $3
 )
 SELECT n.node_uid, p.input_kind, p.input_id, p.source_time FROM nodes n
 JOIN LATERAL (
  SELECT input_kind,input_id,source_time FROM correlation.pending_inputs
  WHERE node_uid=n.node_uid AND source_time < $2
  ORDER BY received_at,input_kind,input_id LIMIT $4
 ) p ON true ORDER BY n.node_uid,p.source_time,p.input_kind,p.input_id`, q.after, cutoff, queueNodes, queueInputs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evaluation
	// Group by source-time minute rather than min/max across the node's entire
	// backlog. Ten minutes of overlap include late connects/state/deny records.
	type key struct {
		node   uuid.UUID
		minute time.Time
	}
	groups := map[key]int{}
	last := uuid.Nil
	nodeCount := 0
	for rows.Next() {
		var node uuid.UUID
		var kind *string
		var id *uuid.UUID
		var at *time.Time
		if err := rows.Scan(&node, &kind, &id, &at); err != nil {
			return nil, err
		}
		if node != last {
			nodeCount++
		}
		last = node
		if kind == nil {
			continue
		}
		input := Input{Kind: *kind, ID: *id}
		k := key{node, at.UTC().Truncate(time.Minute)}
		i, ok := groups[k]
		if !ok {
			i = len(out)
			groups[k] = i
			to := k.minute.Add(time.Minute + Rewind)
			if to.After(cutoff) {
				to = cutoff
			}
			out = append(out, Evaluation{Node: node, From: k.minute.Add(-Rewind), To: to})
		}
		out[i].Inputs = append(out[i].Inputs, input)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if last == uuid.Nil && q.after != uuid.Nil {
		q.after = uuid.Nil
		return q.Pending(ctx, now) // wrap in the same tick, never waste an empty page
	}
	q.after = last
	if nodeCount < queueNodes {
		q.after = uuid.Nil
	}
	return out, nil
}

func (q *PoolQueue) Complete(ctx context.Context, e Evaluation) error {
	tx, err := q.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	batch := &pgx.Batch{}
	for _, input := range e.Inputs {
		batch.Queue(`DELETE FROM correlation.pending_inputs WHERE input_kind=$1 AND input_id=$2`, input.Kind, input.ID)
	}
	results := tx.SendBatch(ctx, batch)
	if err := results.Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
