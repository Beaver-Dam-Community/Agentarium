-- name: Clock :one
SELECT statement_timestamp()::timestamptz AS now;

-- name: LockCursor :one
SELECT last_received_at, last_event_id FROM evidence.collector_cursors
WHERE feed = sqlc.arg(feed)::text FOR UPDATE;

-- name: SaveCursor :exec
INSERT INTO evidence.collector_cursors (feed, last_received_at, last_event_id, updated_at)
VALUES (sqlc.arg(feed)::text, sqlc.arg(last_received_at)::timestamptz, sqlc.arg(last_event_id)::uuid, statement_timestamp())
ON CONFLICT (feed) DO UPDATE SET last_received_at = EXCLUDED.last_received_at,
  last_event_id = EXCLUDED.last_event_id, updated_at = EXCLUDED.updated_at;

-- name: SchedulePoll :exec
-- A new trigger for an action with an existing schedule re-opens it now; the
-- first deadline is kept.
INSERT INTO evidence.receipt_polls (action_id, first_seen_at, deadline_at, next_poll_at, polls)
VALUES (sqlc.arg(action_id)::uuid, sqlc.arg(now)::timestamptz, sqlc.arg(deadline_at)::timestamptz, sqlc.arg(now)::timestamptz, 0)
ON CONFLICT (action_id) DO UPDATE SET next_poll_at = EXCLUDED.next_poll_at;

-- name: NextDuePoll :one
SELECT action_id, first_seen_at, deadline_at, next_poll_at, polls FROM evidence.receipt_polls
WHERE next_poll_at IS NOT NULL AND next_poll_at <= sqlc.arg(now)::timestamptz
ORDER BY next_poll_at, action_id LIMIT 1 FOR UPDATE SKIP LOCKED;

-- name: UpdatePoll :exec
UPDATE evidence.receipt_polls SET next_poll_at = sqlc.narg(next_poll_at)::timestamptz, polls = polls + 1
WHERE action_id = sqlc.arg(action_id)::uuid;

-- name: LatestObservation :one
SELECT revision, rule_id, evidence_level FROM evidence.destination_observations
WHERE action_id = sqlc.arg(action_id)::uuid ORDER BY revision DESC LIMIT 1;

-- name: InsertObservation :exec
INSERT INTO evidence.destination_observations
  (action_id, revision, attempt_id, tenant, evidence_level, rule_id, receipt_digest, effect_count, source_time, event_id)
VALUES (sqlc.arg(action_id)::uuid, sqlc.arg(revision)::integer, sqlc.narg(attempt_id)::uuid, sqlc.arg(tenant)::text,
  sqlc.arg(evidence_level)::text, sqlc.arg(rule_id)::text, sqlc.narg(receipt_digest)::text, sqlc.narg(effect_count)::integer,
  sqlc.arg(source_time)::timestamptz, sqlc.arg(event_id)::uuid);
