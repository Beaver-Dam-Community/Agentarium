//go:build integration

package sessions

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The coordinator (PR #38, services/coordinator/internal/dispatch/budget.go)
// consumes and restores service session counters. That code is not on this
// branch, so these helpers run the same SQL the coordinator uses for the
// service_scope basis, in the same lock order and READ COMMITTED: a
// reservation consumes one use, a release (adapter outcome or permit-expiry
// sweeper) gives it back. The attempt and reservation state checks of the
// coordinator (which make a duplicate release a no-op) are not reproduced.

var errExhausted = errors.New("TOOL_BUDGET_EXHAUSTED")

// coordSession is lockSession for a service session: the row FOR UPDATE,
// whether it is live, and its candidate (nil issue/candidate without one).
func coordSession(ctx context.Context, tx pgx.Tx, id string) (live bool, issue, cand *uuid.UUID, err error) {
	err = tx.QueryRow(ctx, `
SELECT state = 'active' AND expires_at > statement_timestamp(), issue_id, candidate_id
FROM identity.service_sessions WHERE service_session_id = $1 FOR UPDATE`, id).Scan(&live, &issue, &cand)
	return
}

// coordLockCounters is lockForReserve / lockForRestore: the session counter
// row, then the candidate counter row when the session has a candidate.
func coordLockCounters(ctx context.Context, tx pgx.Tx, id, counter string, issue, cand *uuid.UUID) error {
	if err := tx.QueryRow(ctx, `SELECT 1 FROM identity.service_session_counters
WHERE service_session_id = $1 AND counter = $2 FOR UPDATE`, id, counter).Scan(new(int)); err != nil {
		return err
	}
	if cand == nil {
		return nil
	}
	return tx.QueryRow(ctx, `SELECT 1 FROM identity.issue_candidate_counters
WHERE issue_id = $1 AND candidate_id = $2 AND counter = $3 FOR UPDATE`, *issue, *cand, counter).Scan(new(int))
}

func coordConsumeTx(ctx context.Context, tx pgx.Tx, id, counter string) error {
	live, issue, cand, err := coordSession(ctx, tx, id)
	if err != nil {
		return err
	}
	if !live {
		return errExhausted
	}
	if err := coordLockCounters(ctx, tx, id, counter, issue, cand); err != nil {
		return err
	}
	if cand != nil {
		// The candidate's usage is checked against this session's maximum.
		tag, err := tx.Exec(ctx, `
UPDATE identity.issue_candidate_counters cc SET used_value = cc.used_value + 1
FROM identity.service_session_counters sc
WHERE cc.issue_id = $1 AND cc.candidate_id = $2 AND cc.counter = $3
  AND sc.service_session_id = $4 AND sc.counter = $3
  AND cc.used_value < sc.max_value`, *issue, *cand, counter, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errExhausted
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE identity.service_session_counters SET used_value = used_value + 1
WHERE service_session_id = $1 AND counter = $2 AND used_value < max_value`, id, counter)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errExhausted
	}
	return nil
}

var errBooks = errors.New("STATE_STORE_UNAVAILABLE: no use to restore")

func coordRestoreTx(ctx context.Context, tx pgx.Tx, id, counter string) error {
	_, issue, cand, err := coordSession(ctx, tx, id)
	if err != nil {
		return err
	}
	if err := coordLockCounters(ctx, tx, id, counter, issue, cand); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE identity.service_session_counters SET used_value = used_value - 1
WHERE service_session_id = $1 AND counter = $2 AND used_value > 0`, id, counter)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errBooks
	}
	if cand != nil {
		tag, err := tx.Exec(ctx, `UPDATE identity.issue_candidate_counters SET used_value = used_value - 1
WHERE issue_id = $1 AND candidate_id = $2 AND counter = $3 AND used_value > 0`, *issue, *cand, counter)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errBooks
		}
	}
	return nil
}

func coordTx(pool *pgxpool.Pool, fn func(context.Context, pgx.Tx) error) error {
	ctx := context.Background()
	return pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '2s'"); err != nil {
			return err
		}
		return fn(ctx, tx)
	})
}

func consume(pool *pgxpool.Pool, id, counter string) error {
	return coordTx(pool, func(ctx context.Context, tx pgx.Tx) error { return coordConsumeTx(ctx, tx, id, counter) })
}

func restore(pool *pgxpool.Pool, id, counter string) error {
	return coordTx(pool, func(ctx context.Context, tx pgx.Tx) error { return coordRestoreTx(ctx, tx, id, counter) })
}

// use consumes n uses through a session, standing in for the coordinator.
func use(t *testing.T, pool *pgxpool.Pool, id, counter string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := consume(pool, id, counter); err != nil {
			t.Fatalf("consume %d of %d %s on %s: %v", i+1, n, counter, id, err)
		}
	}
}

func mustExhaust(t *testing.T, pool *pgxpool.Pool, id, counter string) {
	t.Helper()
	if err := consume(pool, id, counter); !errors.Is(err, errExhausted) {
		t.Fatalf("consume %s on %s: %v, want exhausted", counter, id, err)
	}
}

func mustRestore(t *testing.T, pool *pgxpool.Pool, id, counter string) {
	t.Helper()
	if err := restore(pool, id, counter); err != nil {
		t.Fatalf("restore %s on %s: %v", counter, id, err)
	}
}

// candUsed is the candidate's authoritative usage of one counter.
func candUsed(t *testing.T, pool *pgxpool.Pool, issue, cand, counter string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `
SELECT used_value FROM identity.issue_candidate_counters WHERE issue_id = $1 AND candidate_id = $2 AND counter = $3`,
		issue, cand, counter).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// checkBooks asserts that every candidate counter is the sum of its sessions'
// own uses.
func checkBooks(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var bad int
	if err := pool.QueryRow(context.Background(), `
SELECT count(*) FROM identity.issue_candidate_counters cc
WHERE cc.used_value <> (
    SELECT coalesce(sum(sc.used_value), 0) FROM identity.service_session_counters sc
    JOIN identity.service_sessions s USING (service_session_id)
    WHERE s.issue_id = cc.issue_id AND s.candidate_id = cc.candidate_id AND sc.counter = cc.counter)`).Scan(&bad); err != nil {
		t.Fatal(err)
	}
	if bad != 0 {
		t.Fatalf("%d candidate counters differ from the sum of their sessions", bad)
	}
}

func reissue(t *testing.T, s *Service, issue, cand string) string {
	t.Helper()
	out, err := s.CreateService(context.Background(), proposer, proposalReq(issue, cand))
	if err != nil {
		t.Fatal(err)
	}
	return out.ServiceSessionID
}

// Rina's case: A at 8/8 with its last permit unclaimed, A expires, B is
// issued, then A's permit is released (expiry sweeper or a credential failure
// before the claim). The use returns to the candidate, so B gets it.
func TestCandidateLateReleaseAfterReissue(t *testing.T) {
	s, pool := setup(t)
	issue, cand := uuid.NewString(), uuid.NewString()
	a := reissue(t, s, issue, cand)
	use(t, pool, a, "model", 8)
	mustExhaust(t, pool, a, "model")
	expire(t, pool, a)

	b := reissue(t, s, issue, cand)
	if inh := lastEvent(t, s).Payload["inherited_used"].(map[string]int); inh["model"] != 8 {
		t.Fatalf("inherited_used %v", inh)
	}
	if c := counters(t, pool, b); c["model"] != [2]int{0, 8} {
		t.Fatalf("B counters %v", c)
	}
	mustExhaust(t, pool, b, "model")

	mustRestore(t, pool, a, "model") // late release of A's last permit
	if got := candUsed(t, pool, issue, cand, "model"); got != 7 {
		t.Fatalf("candidate used %d after release, want 7", got)
	}
	use(t, pool, b, "model", 1)
	mustExhaust(t, pool, b, "model")
	if got := candUsed(t, pool, issue, cand, "model"); got != 8 {
		t.Fatalf("candidate used %d, want 8", got)
	}
	if ca, cb := counters(t, pool, a), counters(t, pool, b); ca["model"] != [2]int{7, 8} || cb["model"] != [2]int{1, 8} {
		t.Fatalf("A %v, B %v", ca, cb)
	}
	checkBooks(t, pool)

	// C after B starts from the real usage, 8, not more.
	expire(t, pool, b)
	c := reissue(t, s, issue, cand)
	if inh := lastEvent(t, s).Payload["inherited_used"].(map[string]int); inh["model"] != 8 {
		t.Fatalf("C inherited_used %v", inh)
	}
	mustExhaust(t, pool, c, "model")
}

// A → B → C, then A's late release: the use goes to C, the live session.
func TestCandidateLateReleaseTwoReissues(t *testing.T) {
	s, pool := setup(t)
	issue, cand := uuid.NewString(), uuid.NewString()
	a := reissue(t, s, issue, cand)
	use(t, pool, a, "model", 8)
	expire(t, pool, a)
	b := reissue(t, s, issue, cand)
	mustExhaust(t, pool, b, "model")
	expire(t, pool, b)
	c := reissue(t, s, issue, cand)
	mustExhaust(t, pool, c, "model")

	mustRestore(t, pool, a, "model")
	use(t, pool, c, "model", 1)
	mustExhaust(t, pool, c, "model")
	if got := candUsed(t, pool, issue, cand, "model"); got != 8 {
		t.Fatalf("candidate used %d", got)
	}
	checkBooks(t, pool)
}

// Two releases of A arrive after B's issue, in the reverse order of their
// reservations (one read_tools, one model, then a second model).
func TestCandidateReleasesReverseOrder(t *testing.T) {
	s, pool := setup(t)
	issue, cand := uuid.NewString(), uuid.NewString()
	a := reissue(t, s, issue, cand)
	use(t, pool, a, "model", 8)
	use(t, pool, a, "read_tools", 2)
	expire(t, pool, a)
	b := reissue(t, s, issue, cand)
	if inh := lastEvent(t, s).Payload["inherited_used"].(map[string]int); inh["model"] != 8 || inh["read_tools"] != 2 {
		t.Fatalf("inherited_used %v", inh)
	}
	mustRestore(t, pool, a, "read_tools") // the later reservation first
	mustRestore(t, pool, a, "model")
	mustRestore(t, pool, a, "model")
	if m, r := candUsed(t, pool, issue, cand, "model"), candUsed(t, pool, issue, cand, "read_tools"); m != 6 || r != 1 {
		t.Fatalf("candidate model %d read_tools %d", m, r)
	}
	use(t, pool, b, "model", 2)
	use(t, pool, b, "read_tools", 1)
	mustExhaust(t, pool, b, "model")
	mustExhaust(t, pool, b, "read_tools")
	checkBooks(t, pool)
}

// The books check of the restore: a session cannot give back more than it
// consumed, and neither can its candidate. (A repeated release of one attempt
// is a no-op in the coordinator before it reaches the counters; that check is
// in PR #38.)
func TestCandidateRestoreBooks(t *testing.T) {
	s, pool := setup(t)
	issue, cand := uuid.NewString(), uuid.NewString()
	a := reissue(t, s, issue, cand)
	use(t, pool, a, "model", 1)
	expire(t, pool, a)
	b := reissue(t, s, issue, cand)
	if err := restore(pool, b, "model"); !errors.Is(err, errBooks) {
		t.Fatalf("restore on B with no uses: %v", err)
	}
	mustRestore(t, pool, a, "model")
	if err := restore(pool, a, "model"); !errors.Is(err, errBooks) {
		t.Fatalf("second restore on A: %v", err)
	}
	if got := candUsed(t, pool, issue, cand, "model"); got != 0 {
		t.Fatalf("candidate used %d", got)
	}
	checkBooks(t, pool)
}

// A release of A still running when B is issued: the re-issue waits for it
// and starts from the restored usage.
func TestCandidateReleaseConcurrentWithReissue(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	issue, cand := uuid.NewString(), uuid.NewString()
	a := reissue(t, s, issue, cand)
	use(t, pool, a, "model", 8)
	expire(t, pool, a)

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := coordRestoreTx(ctx, tx, a, "model"); err != nil {
		t.Fatal(err)
	}
	type result struct {
		out *ServiceResponse
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := s.CreateService(ctx, proposer, proposalReq(issue, cand))
		done <- result{out, err}
	}()
	waitForLock(t, pool, done)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if inh := lastEvent(t, s).Payload["inherited_used"].(map[string]int); inh["model"] != 7 {
		t.Fatalf("inherited_used %v, want model 7", inh)
	}
	use(t, pool, r.out.ServiceSessionID, "model", 1)
	mustExhaust(t, pool, r.out.ServiceSessionID, "model")
	checkBooks(t, pool)
}

// waitForLock fails unless the call behind done is blocked on a row lock.
func waitForLock[T any](t *testing.T, pool *pgxpool.Pool, done chan T) {
	t.Helper()
	ctx := context.Background()
	waiting := false
	for deadline := time.Now().Add(1500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		var n int
		if err := pool.QueryRow(ctx, `
SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			waiting = true
			break
		}
	}
	select {
	case r := <-done:
		t.Fatalf("call did not wait for the lock: %+v", r)
	default:
	}
	if !waiting {
		t.Fatal("call is not waiting on a lock")
	}
}

// Releases and consumptions racing with re-issues keep the books: the
// candidate counter stays the sum of its sessions and never passes the cap.
func TestCandidateCountersUnderConcurrency(t *testing.T) {
	s, pool := setup(t)
	issue, cand := uuid.NewString(), uuid.NewString()
	a := reissue(t, s, issue, cand)
	use(t, pool, a, "model", 8)
	expire(t, pool, a)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var issued []string
	// Three releases and three re-issues: at most four commits can make one
	// re-issue retry, inside its five attempts.
	for i := 0; i < 3; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := restore(pool, a, "model"); err != nil {
				t.Errorf("restore: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			out, err := s.CreateService(context.Background(), proposer, proposalReq(issue, cand))
			var e *Error
			switch {
			case err == nil:
				mu.Lock()
				issued = append(issued, out.ServiceSessionID)
				mu.Unlock()
			case !errors.As(err, &e) || e.Code != CodeServiceSessionActive:
				t.Errorf("re-issue: %v", err)
			}
		}()
	}
	wg.Wait()
	if len(issued) != 1 {
		t.Fatalf("%d sessions issued", len(issued))
	}
	if got := candUsed(t, pool, issue, cand, "model"); got != 5 {
		t.Fatalf("candidate used %d, want 5", got)
	}
	var wg2 sync.WaitGroup
	var ok, exhausted int
	for i := 0; i < 8; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			err := consume(pool, issued[0], "model")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, errExhausted):
				exhausted++
			default:
				t.Errorf("consume: %v", err)
			}
		}()
	}
	wg2.Wait()
	if ok != 3 || exhausted != 5 {
		t.Fatalf("consumed %d, exhausted %d", ok, exhausted)
	}
	checkBooks(t, pool)
}

// Two candidates of one issue have separate counters; releases of one do not
// reach the other, and the issue total stays at 2 × 8.
func TestCandidateCountersIndependent(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	issue := uuid.NewString()
	c1, c2 := uuid.NewString(), uuid.NewString()
	a1, a2 := reissue(t, s, issue, c1), reissue(t, s, issue, c2)
	use(t, pool, a1, "model", 8)
	use(t, pool, a2, "model", 8)
	expire(t, pool, a1)
	expire(t, pool, a2)
	b1, b2 := reissue(t, s, issue, c1), reissue(t, s, issue, c2)
	mustRestore(t, pool, a1, "model")
	mustExhaust(t, pool, b2, "model")
	use(t, pool, b1, "model", 1)
	mustExhaust(t, pool, b1, "model")
	if u1, u2 := candUsed(t, pool, issue, c1, "model"), candUsed(t, pool, issue, c2, "model"); u1 != 8 || u2 != 8 {
		t.Fatalf("candidates %d %d", u1, u2)
	}
	var total int
	pool.QueryRow(ctx, `SELECT sum(used_value) FROM identity.issue_candidate_counters WHERE issue_id = $1 AND counter = 'model'`, issue).Scan(&total)
	if total != 16 {
		t.Fatalf("issue model usage %d", total)
	}
	checkBooks(t, pool)
}

// Sessions without a candidate keep the per-session counter path.
func TestNoCandidateCounters(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	checker := RuntimePrincipal{SAN: "spiffe://agentarium.internal/ns/agent-control/sa/intent-checker", Namespace: "agent-control", KSA: "intent-checker"}
	action := uuid.NewString()
	out, err := s.CreateService(ctx, checker, ServiceRequest{Profile: "intent_check", ActionID: &action, Tenant: "hackathon"})
	if err != nil {
		t.Fatal(err)
	}
	use(t, pool, out.ServiceSessionID, "model", 1)
	mustExhaust(t, pool, out.ServiceSessionID, "model")
	mustRestore(t, pool, out.ServiceSessionID, "model")
	use(t, pool, out.ServiceSessionID, "model", 1)
	if c := counters(t, pool, out.ServiceSessionID); c["model"] != [2]int{1, 1} {
		t.Fatalf("counters %v", c)
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.issue_candidate_counters`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d candidate counter rows", n)
	}
}

// A failed audit append rolls back the candidate rows of a first issue and
// leaves a re-issue's candidate counters as they were.
func TestCandidateCountersAuditRollback(t *testing.T) {
	ctx := context.Background()
	s, pool := setup(t)
	rec := s.Audit.(*recorder)
	issue, cand := uuid.NewString(), uuid.NewString()
	rec.fail = true
	if _, err := s.CreateService(ctx, proposer, proposalReq(issue, cand)); err == nil {
		t.Fatal("first issue succeeded without audit")
	}
	var n [3]int
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.issue_candidates WHERE issue_id = $1`, issue).Scan(&n[0])
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.issue_candidate_counters WHERE issue_id = $1`, issue).Scan(&n[1])
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.service_sessions WHERE issue_id = $1`, issue).Scan(&n[2])
	if n != [3]int{} {
		t.Fatalf("rows left after a failed first issue: %v", n)
	}
	rec.fail = false
	a := reissue(t, s, issue, cand)
	use(t, pool, a, "model", 3)
	expire(t, pool, a)
	rec.fail = true
	if _, err := s.CreateService(ctx, proposer, proposalReq(issue, cand)); err == nil {
		t.Fatal("re-issue succeeded without audit")
	}
	rec.fail = false
	if got := candUsed(t, pool, issue, cand, "model"); got != 3 {
		t.Fatalf("candidate used %d", got)
	}
	pool.QueryRow(ctx, `SELECT count(*) FROM identity.service_sessions WHERE candidate_id = $1`, cand).Scan(&n[0])
	if n[0] != 1 {
		t.Fatalf("%d sessions", n[0])
	}
	checkBooks(t, pool)
}
