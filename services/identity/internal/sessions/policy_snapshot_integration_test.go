//go:build integration

package sessions

import (
	"context"
	"testing"
)

// Uses the actual signed-bundle loader and PostgreSQL session transaction.
// Audit remains the existing fixture recorder here; PR #141 independently
// verifies real audit_append wiring. This is not a deployed identity test.
func TestSnapshotPolicySessionBudgets(t *testing.T) {
	s, db := setup(t)
	ctx := context.Background()
	fixture, loader := newPolicyFixture(t)
	s.Policy = fixture.policy(loader)
	if _, err := s.Create(ctx, alice, k8sRequest()); code(t, err) != "POLICY_UNAVAILABLE" {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM identity.sessions").Scan(&count); err != nil || count != 0 {
		t.Fatalf("unloaded policy wrote session: %d %v", count, err)
	}
	fixture.put(t, "first", policyRules(13), true)
	if err := loader.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, alice, k8sRequest()); code(t, err) != "POLICY_UNAVAILABLE" { // no active_policy row yet
		t.Fatal("preloaded bundle accepted", err)
	}
	fixture.activate(loader)
	first, err := s.Create(ctx, alice, k8sRequest())
	if err != nil {
		t.Fatal(err)
	}
	checkBudget := func(id string, want int) {
		t.Helper()
		var max, used int
		if err := db.QueryRow(ctx, "SELECT max_actions,used_actions FROM identity.session_budgets WHERE session_id=$1 AND standing_rule_id='standing.k8s_read.v1'", id).Scan(&max, &used); err != nil || max != want || used != 0 {
			t.Fatalf("budget: %d/%d want %d/0: %v", max, used, want, err)
		}
	}
	checkBudget(first.SessionID, 13)
	fixture.put(t, "next", policyRules(7), true)
	if err := loader.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, alice, k8sRequest()); code(t, err) != "POLICY_VERSION_MISMATCH" {
		t.Fatal("preloaded update accepted", err)
	}
	fixture.activate(loader)
	next, err := s.Create(ctx, alice, k8sRequest())
	if err != nil {
		t.Fatal(err)
	}
	checkBudget(next.SessionID, 7)
	checkBudget(first.SessionID, 13)
	fixture.put(t, "malformed", nil, true)
	if err := loader.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.activate(loader)
	if _, err := s.Create(ctx, alice, k8sRequest()); code(t, err) != "POLICY_UNAVAILABLE" {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, "SELECT count(*) FROM identity.sessions").Scan(&count); err != nil || count != 2 {
		t.Fatalf("invalid rules wrote session: %d %v", count, err)
	}
}
