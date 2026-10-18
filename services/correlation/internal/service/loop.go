// Package service runs the correlation evaluations on a fixed cadence: the
// TASK-10 3.1 correlation worker, the 3.7 NetworkFinding evaluation and the
// 3.2 risk-event evaluator, per node with stored kernel or netpol records.
package service

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/risk"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/worker"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/netpol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Rewind re-evaluates the end of the previous window so late kernel,
// lifecycle and netpol records reach the stores' revision rules. Every step
// is idempotent: unchanged results add no revision and a repeated hold
// request returns the open hold.
const Rewind = 5 * time.Minute

type Worker interface {
	Run(ctx context.Context, node uuid.UUID, from, to, asOf time.Time) (int, error)
}
type Netpol interface {
	Evaluate(ctx context.Context, node uuid.UUID, from, to, asOf time.Time) error
}
type Risk interface {
	Evaluate(ctx context.Context, node uuid.UUID, from, to time.Time) error
}

type Loop struct {
	Queue    Queue
	Nodes    func(ctx context.Context, from, to time.Time) ([]uuid.UUID, error)
	Worker   Worker
	Netpol   Netpol
	Risk     Risk
	Interval time.Duration
	// Start is the first window start (a bounded lookback at process start).
	Start time.Time
}

// Window is the evaluated range at now: from the rewound cursor to the point
// the worker may correlate (MinDelay).
func Window(cursor, now time.Time) (time.Time, time.Time) {
	to := now.Add(-worker.MinDelay)
	from := cursor.Add(-Rewind)
	return from, to
}

// evaluate keeps risk after the correlation revision for the same window.
func (l *Loop) evaluate(ctx context.Context, e Evaluation, now time.Time) error {
	if _, err := l.Worker.Run(ctx, e.Node, e.From, e.To, now); err != nil {
		return err
	}
	if err := l.Netpol.Evaluate(ctx, e.Node, e.From, e.To, now); err != nil {
		return err
	}
	return l.Risk.Evaluate(ctx, e.Node, e.From, e.To)
}

// Tick drains durable pending inputs and revisits the recent source-time tail
// for late join evidence. Queue acknowledgments advance independently per window;
// failures never expand another node's query range.
func (l *Loop) Tick(ctx context.Context, cursor, now time.Time) (time.Time, error) {
	var failed error
	if l.Queue != nil {
		pending, err := l.Queue.Pending(ctx, now)
		failed = errors.Join(failed, err)
		for _, e := range pending {
			if err := l.evaluate(ctx, e, now); err != nil {
				failed = errors.Join(failed, err)
				continue
			}
			failed = errors.Join(failed, l.Queue.Complete(ctx, e))
		}
	}
	from, to := Window(cursor, now)
	// Recovery is driven by pending input IDs; the tail must stay bounded even
	// after a long outage or repeated failures.
	if from.Before(to.Add(-2 * Rewind)) {
		from = to.Add(-2 * Rewind)
	}
	if !to.After(from) {
		return cursor, failed
	}
	nodes, err := l.Nodes(ctx, from, to)
	failed = errors.Join(failed, err)
	for _, node := range nodes {
		failed = errors.Join(failed, l.evaluate(ctx, Evaluation{Node: node, From: from, To: to}, now))
	}
	return to, failed
}

func (l *Loop) Run(ctx context.Context) {
	cursor := l.Start
	ticker := time.NewTicker(l.Interval)
	defer ticker.Stop()
	for {
		next, err := l.Tick(ctx, cursor, time.Now().UTC())
		if err != nil && ctx.Err() == nil {
			log.Print("correlation window failed; retrying: ", err)
		}
		cursor = next
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// PoolNodes lists nodes with stored kernel events or netpol records in the
// window (TASK-07 correlation_reader and correlation_writer grants).
func PoolNodes(pool *pgxpool.Pool) func(ctx context.Context, from, to time.Time) ([]uuid.UUID, error) {
	return func(ctx context.Context, from, to time.Time) ([]uuid.UUID, error) {
		rows, err := pool.Query(ctx, `SELECT node_uid FROM audit.kernel_events WHERE source_time >= $1 AND source_time < $2
			UNION SELECT node_uid FROM correlation.network_policy_records WHERE source_time >= $1 AND source_time < $2`, from, to)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []uuid.UUID
		for rows.Next() {
			var id pgtype.UUID
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			out = append(out, uuid.UUID(id.Bytes))
		}
		return out, rows.Err()
	}
}

// NetpolEvaluator adapts netpol.Store.Evaluate.
type NetpolEvaluator struct {
	Store     netpol.Store
	Workloads netpol.WorkloadResolver
	Allowed   netpol.AllowTable
}

func (n NetpolEvaluator) Evaluate(ctx context.Context, node uuid.UUID, from, to, asOf time.Time) error {
	_, err := n.Store.Evaluate(ctx, node, from, to, asOf, n.Workloads, n.Allowed)
	return err
}

// RiskEvaluator loads candidates, evaluates them and requests holds.
type RiskEvaluator struct {
	Pool      *pgxpool.Pool
	Workloads risk.WorkloadResolver
	Allowed   risk.AllowTable
	Config    risk.Config
	Holds     risk.HoldClient
}

func (r RiskEvaluator) Evaluate(ctx context.Context, node uuid.UUID, from, to time.Time) error {
	events, roots, err := risk.Load(ctx, r.Pool, node, from, to, r.Workloads, r.Allowed)
	if err != nil {
		return err
	}
	cfg := r.Config
	cfg.ContainerRoots = roots
	decisions, _ := risk.Evaluate(events, cfg)
	var failed error
	for _, d := range decisions {
		if _, err := r.Holds.Request(ctx, d); errors.Is(err, risk.ErrRejected) {
			// A rejected request is a principal/detail configuration error:
			// it is reported, not retried forever, and never counted as held.
			log.Printf("risk_event hold for %s rejected (kernel_event:%s)", d.WorkloadID, d.KernelEventID)
		} else if err != nil {
			failed = errors.Join(failed, err)
		}
	}
	return failed
}
