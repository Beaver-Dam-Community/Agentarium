package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/worker"
	"github.com/google/uuid"
)

type call struct {
	step     string
	node     uuid.UUID
	from, to time.Time
}

type fake struct {
	calls   *[]call
	failFor uuid.UUID
}

func (f fake) Run(_ context.Context, node uuid.UUID, from, to, _ time.Time) (int, error) {
	*f.calls = append(*f.calls, call{"worker", node, from, to})
	if node == f.failFor {
		return 0, errors.New("db")
	}
	return 0, nil
}

type netpolFake struct{ calls *[]call }

func (f netpolFake) Evaluate(_ context.Context, node uuid.UUID, from, to, _ time.Time) error {
	*f.calls = append(*f.calls, call{"netpol", node, from, to})
	return nil
}

type riskFake struct{ calls *[]call }

func (f riskFake) Evaluate(_ context.Context, node uuid.UUID, from, to time.Time) error {
	*f.calls = append(*f.calls, call{"risk", node, from, to})
	return nil
}

func TestTick(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	calls := []call{}
	l := &Loop{Nodes: func(context.Context, time.Time, time.Time) ([]uuid.UUID, error) { return []uuid.UUID{a, b}, nil },
		Worker: fake{calls: &calls}, Netpol: netpolFake{&calls}, Risk: riskFake{&calls}}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	cursor := now.Add(-10 * time.Minute)
	next, err := l.Tick(context.Background(), cursor, now)
	if err != nil || !next.Equal(now.Add(-worker.MinDelay)) {
		t.Fatalf("next %v %v", next, err)
	}
	// Each node: worker before risk, over the rewound window ending at MinDelay.
	if len(calls) != 6 || calls[0].step != "worker" || calls[2].step != "risk" || !calls[0].from.Equal(next.Add(-2*Rewind)) || !calls[0].to.Equal(next) {
		t.Fatalf("calls %+v", calls)
	}
	// A failed node leaves its durable queue entry pending, without pinning the tail.
	calls = calls[:0]
	l.Worker = fake{calls: &calls, failFor: a}
	kept, err := l.Tick(context.Background(), cursor, now)
	if err == nil || !kept.Equal(next) {
		t.Fatalf("tail did not advance independently: %v %v", kept, err)
	}
	for _, c := range calls {
		if c.node == a && c.step != "worker" {
			t.Fatalf("evaluated after worker failure: %+v", c)
		}
	}
	// Nothing to evaluate before MinDelay has passed.
	if next, err := l.Tick(context.Background(), now, now.Add(-time.Hour)); err != nil || !next.Equal(now) {
		t.Fatalf("empty window %v %v", next, err)
	}
}

type memoryQueue struct {
	pending   []Evaluation
	completed []Evaluation
}

func (q *memoryQueue) Pending(context.Context, time.Time) ([]Evaluation, error) {
	return q.pending, nil
}
func (q *memoryQueue) Complete(_ context.Context, e Evaluation) error {
	q.completed = append(q.completed, e)
	return nil
}

func TestPendingReplayAndIndependentNodeProgress(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	a, b := uuid.New(), uuid.New()
	old := now.Add(-24 * time.Hour)
	q := &memoryQueue{pending: []Evaluation{
		{Node: a, From: old, To: old.Add(time.Minute)},
		{Node: b, From: old, To: old.Add(time.Minute)},
	}}
	calls := []call{}
	l := &Loop{Queue: q, Nodes: func(context.Context, time.Time, time.Time) ([]uuid.UUID, error) { return nil, nil },
		Worker: fake{calls: &calls, failFor: a}, Netpol: netpolFake{&calls}, Risk: riskFake{&calls}}
	next, err := l.Tick(context.Background(), now.Add(-time.Hour), now)
	if err == nil || !next.Equal(now.Add(-worker.MinDelay)) {
		t.Fatalf("progress %v %v", next, err)
	}
	if len(q.completed) != 1 || q.completed[0].Node != b {
		t.Fatalf("receipts %+v", q.completed)
	}
	if len(calls) != 4 || calls[3].step != "risk" || calls[3].node != b || !calls[3].from.Equal(old) {
		t.Fatalf("replayed evaluations %+v", calls)
	}
	// A later retry succeeds for the failed node's unchanged bounded window.
	q.pending = q.pending[:1]
	l.Worker = fake{calls: &calls}
	if _, err := l.Tick(context.Background(), next, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(q.completed) != 2 || q.completed[1].Node != a || q.completed[1].To.Sub(q.completed[1].From) != time.Minute {
		t.Fatalf("retry %+v", q.completed)
	}
}
