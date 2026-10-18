-- name: ReadPage :many
SELECT event_id,event_type,tenant,action_id,attempt_id,source_time,received_at,safe_payload
FROM audit.collector_feed
WHERE tenant=sqlc.arg(tenant)::text
  AND (sqlc.narg(after_time)::timestamptz IS NULL OR
       (received_at,event_id)>(sqlc.narg(after_time)::timestamptz,sqlc.narg(after_id)::uuid))
ORDER BY received_at,event_id LIMIT sqlc.arg(page_limit)::integer;

-- name: ReadTarget :one
SELECT action_id,tenant,operation_id,canonical_target
FROM decisions.actions_target_view
WHERE tenant=sqlc.arg(tenant)::text AND action_id=sqlc.arg(action_id)::uuid;

-- name: ReadActionEvents :many
SELECT event_id,event_type,attempt_id,received_at,safe_payload
FROM audit.collector_feed
WHERE tenant=sqlc.arg(tenant)::text AND action_id=sqlc.arg(action_id)::uuid
ORDER BY received_at,event_id LIMIT sqlc.arg(page_limit)::integer;
