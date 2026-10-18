package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// testWatchGaps checks the #178 receiver on real PostgreSQL: exact SAN and
// allowlisted scope only, idempotent on gap_id with conflict on a different
// body, and the gap committed with its audit event or not at all.
func testWatchGaps(t *testing.T, s *Store, db *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	exec("INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES ('agent-observe','pod-watcher','service',true) ON CONFLICT DO NOTHING")
	exec("INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,issued_at,expires_at) VALUES ('w1',$1,'agent-observe','pod-watcher',now()-interval '1 minute',now()+interval '1 hour')", health.PodWatcherSAN)
	exec("INSERT INTO audit.producer_event_grants VALUES('health-source','observation_gap_recorded','*') ON CONFLICT DO NOTHING")
	exec("INSERT INTO health.watcher_scopes VALUES ('cluster/agent-exec')")
	watcher := health.Peer{SAN: health.PodWatcherSAN, Serial: "w1"}
	end := time.Now().UTC().Truncate(time.Millisecond)
	body := func(id, scope string, start time.Time) []byte {
		return []byte(`{"scope":"` + scope + `","gap":{"gap_id":"` + id + `","stage":"lifecycle_capture","reason":"WATCH_HISTORY_EXPIRED","source_epoch":"` + "0123456789abcdef0123456789abcdef_1" + `","start_at":"` + start.Format(time.RFC3339Nano) + `","end_at":"` + end.Format(time.RFC3339Nano) + `","loss_count":null,"count_quality":"unknown","recovery_state":"unrecoverable","evidence_refs":[]}}`)
	}
	decode := func(raw []byte) health.WatchGapRequest {
		t.Helper()
		r, err := health.DecodeWatchGap(raw)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	id := uuid.NewString()
	request := decode(body(id, "cluster/agent-exec", end.Add(-time.Minute)))
	if _, err := s.ReceiveWatchGap(ctx, health.Peer{SAN: "spiffe://agentarium.internal/ns/agent-observe/sa/other", Serial: "w1"}, request); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("wrong SAN: %v", err)
	}
	if _, err := s.ReceiveWatchGap(ctx, watcher, decode(body(id, "cluster/other", end.Add(-time.Minute)))); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("scope outside the allowlist: %v", err)
	}
	exec("UPDATE identity.issued_certificates SET revoked_at=now() WHERE serial='w1'")
	if _, err := s.ReceiveWatchGap(ctx, watcher, request); !errors.Is(err, health.ErrForbidden) {
		t.Fatalf("revoked certificate: %v", err)
	}
	exec("UPDATE identity.issued_certificates SET revoked_at=NULL WHERE serial='w1'")
	exec("DELETE FROM audit.producer_event_grants WHERE event_type='observation_gap_recorded'")
	if _, err := s.ReceiveWatchGap(ctx, watcher, request); err == nil || count("SELECT count(*) FROM health.observation_gaps WHERE gap_id=$1::uuid", id) != 0 {
		t.Fatalf("gap stored without its audit event: %v", err)
	}
	exec("INSERT INTO audit.producer_event_grants VALUES('health-source','observation_gap_recorded','*')")
	first, err := s.ReceiveWatchGap(ctx, watcher, request)
	if err != nil || first.Result != "created" || first.GapID != id {
		t.Fatalf("created %+v %v", first, err)
	}
	if count(`SELECT count(*) FROM health.observation_gaps WHERE gap_id=$1::uuid AND source_id=$2 AND node_uid IS NULL AND boot_id IS NULL
		AND sequence_from IS NULL AND loss_count IS NULL AND count_quality='unknown' AND recovery_state='unrecoverable' AND created_by='TASK-10'
		AND scope='cluster/agent-exec' AND request_digest=$3`, id, health.PodWatcherSAN, request.Digest) != 1 {
		t.Fatal("stored gap does not follow the #178 field rules")
	}
	if count("SELECT count(*) FROM audit.audit_events WHERE event_type='observation_gap_recorded' AND safe_payload->>'gap_id'=$1 AND authenticated_actor=$2", id, health.PodWatcherSAN) != 1 {
		t.Fatal("observation_gap_recorded missing")
	}
	again, err := s.ReceiveWatchGap(ctx, watcher, decode(body(id, "cluster/agent-exec", end.Add(-time.Minute))))
	if err != nil || again.Result != "existing" || !again.RecordedAt.Equal(first.RecordedAt) {
		t.Fatalf("retry %+v %v", again, err)
	}
	if _, err := s.ReceiveWatchGap(ctx, watcher, decode(body(id, "cluster/agent-exec", end.Add(-2*time.Minute)))); !errors.Is(err, health.ErrConflict) {
		t.Fatalf("different body for the same gap_id: %v", err)
	}
	if count("SELECT count(*) FROM audit.audit_events WHERE event_type='observation_gap_recorded' AND safe_payload->>'gap_id'=$1", id) != 1 {
		t.Fatal("retry appended another audit event")
	}
	// The writer has no direct INSERT on gaps at all: neither receiver-shaped
	// rows nor rows that would skip the receiver rules (NULL scope/digest,
	// another created_by) can be written outside the definer function.
	for name, sql := range map[string]string{
		"created_at":         `INSERT INTO health.observation_gaps(gap_id,stage,reason,source_id,start_at,end_at,count_quality,recovery_state,created_by,created_at) VALUES(gen_random_uuid(),'lifecycle_capture','WATCH_HISTORY_EXPIRED','x',now(),now(),'unknown','unrecoverable','TASK-10',now()-interval '1 day')`,
		"null scope row":     `INSERT INTO health.observation_gaps(gap_id,stage,reason,source_id,start_at,end_at,count_quality,recovery_state,created_by) VALUES(gen_random_uuid(),'lifecycle_capture','WATCH_HISTORY_EXPIRED','x',now(),now(),'unknown','unrecoverable','TASK-10')`,
		"created_by TASK-07": `INSERT INTO health.observation_gaps(gap_id,stage,reason,source_id,start_at,count_quality,recovery_state,created_by) VALUES(gen_random_uuid(),'lifecycle_capture','SEQUENCE_RANGE_ABANDONED','x',now(),'exact','unrecoverable','TASK-07')`,
	} {
		if _, err := s.Pool.Exec(ctx, sql); err == nil {
			t.Fatalf("writer inserted a gap directly: %s", name)
		}
	}
	// The function rejects a missing scope or digest and a non-allowlisted scope.
	call := func(scope, digest any) error {
		_, err := s.Pool.Exec(ctx, "SELECT * FROM health.record_watch_gap(gen_random_uuid(),$1,'e',now()-interval '1 minute',now(),'[]',$2)", scope, digest)
		return err
	}
	for name, err := range map[string]error{
		"null scope":        call(nil, strings.Repeat("a", 64)),
		"null digest":       call("cluster/agent-exec", nil),
		"bad digest":        call("cluster/agent-exec", "xyz"),
		"scope not allowed": call("cluster/other", strings.Repeat("a", 64)),
	} {
		if err == nil {
			t.Fatalf("record_watch_gap accepted %s", name)
		}
	}
	// Whatever the caller passes, created_by and the fixed values are the server's.
	if count("SELECT count(*) FROM health.observation_gaps WHERE request_digest IS NOT NULL AND (created_by<>'TASK-10' OR stage<>'lifecycle_capture' OR source_id<>$1)", health.PodWatcherSAN) != 0 {
		t.Fatal("receiver row with client-chosen fixed values")
	}
	if _, err := s.Pool.Exec(ctx, "INSERT INTO health.watcher_scopes VALUES ('cluster/evil')"); err == nil {
		t.Fatal("writer extended the scope allowlist")
	}
}
