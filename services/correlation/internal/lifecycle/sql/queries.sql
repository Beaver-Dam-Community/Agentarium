-- name: LimitLockWait :exec
SET LOCAL lock_timeout = '2s';

-- name: LockContainer :exec
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(container)::text, 0));

-- name: LatestInstance :one
SELECT interval_id::text, cluster_uid::text, pod_uid::text, node_uid::text,
 boot_id, container_id, restart_instance, cgroup_inode, netns_inode,
 started_at, ended_at, end_quality, mapping_version, source_event_ids::text[] FROM correlation.lifecycle_intervals
WHERE container_id=sqlc.arg(container)::text AND cluster_uid=sqlc.arg(cluster)::text::uuid
AND pod_uid=sqlc.arg(pod)::text::uuid AND node_uid=sqlc.arg(node)::text::uuid
AND boot_id=sqlc.arg(boot)::text
AND restart_instance IS NOT DISTINCT FROM sqlc.narg(restart)::integer
ORDER BY mapping_version DESC LIMIT 1;

-- name: NextMappingVersion :one
SELECT (COALESCE(MAX(mapping_version)::bigint,0)+1)::bigint AS next_version
FROM correlation.lifecycle_intervals WHERE container_id=sqlc.arg(container)::text;

-- name: InsertInterval :exec
INSERT INTO correlation.lifecycle_intervals
(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,restart_instance,
cgroup_inode,netns_inode,started_at,ended_at,end_quality,mapping_version,source_event_ids)
VALUES (sqlc.arg(id)::text::uuid,sqlc.arg(cluster)::text::uuid,sqlc.arg(pod)::text::uuid,
sqlc.arg(node)::text::uuid,sqlc.arg(boot)::text,sqlc.arg(container)::text,
sqlc.narg(restart)::integer,sqlc.narg(cgroup)::bigint,sqlc.narg(netns)::bigint,
sqlc.narg(started_at)::timestamptz,sqlc.narg(ended_at)::timestamptz,
sqlc.arg(end_quality)::text,sqlc.arg(mapping_version)::integer,
sqlc.arg(source_ids)::text[]::uuid[]);

-- name: LatestHistory :many
SELECT interval_id::text, cluster_uid::text, pod_uid::text, node_uid::text,
 boot_id, container_id, restart_instance, cgroup_inode, netns_inode,
 started_at, ended_at, end_quality, mapping_version, source_event_ids::text[] FROM (
 SELECT DISTINCT ON (cluster_uid,pod_uid,node_uid,boot_id,container_id,restart_instance) *
 FROM correlation.lifecycle_intervals
 WHERE cluster_uid=sqlc.arg(cluster)::text::uuid AND container_id=sqlc.arg(container)::text
 ORDER BY cluster_uid,pod_uid,node_uid,boot_id,container_id,restart_instance,mapping_version DESC
) history ORDER BY mapping_version;
