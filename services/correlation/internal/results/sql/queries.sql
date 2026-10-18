-- name: LimitLockWait :exec
SET LOCAL lock_timeout = '2s';

-- name: LockKernelResult :exec
SELECT pg_advisory_xact_lock(hashtextextended('correlation/result/' || sqlc.arg(kernel_id)::text, 0));

-- name: Latest :one
SELECT * FROM correlation.correlations WHERE kernel_event_id = sqlc.arg(kernel_id)::uuid
ORDER BY revision DESC LIMIT 1;

-- name: Insert :exec
INSERT INTO correlation.correlations
(correlation_id,kernel_event_id,revision,action_id,attempt_id,workload_id,confidence,method,evidence_refs,candidate_count,algorithm_version,reason,limitations,created_at)
VALUES(sqlc.arg(id)::uuid,sqlc.arg(kernel_id)::uuid,sqlc.arg(revision)::integer,
       sqlc.narg(action_id)::uuid,sqlc.narg(attempt_id)::uuid,sqlc.narg(workload_id)::text,
       sqlc.arg(confidence)::text,sqlc.arg(method)::text,sqlc.arg(evidence_refs)::jsonb,
       sqlc.arg(candidate_count)::integer,sqlc.arg(algorithm_version)::text,
       sqlc.arg(reason)::text,sqlc.arg(limitations)::text[],sqlc.arg(created_at)::timestamptz);

-- name: AppendAudit :one
SELECT audit.audit_append(sqlc.arg(event)::jsonb, ARRAY['gcs']::text[])::text AS result;
