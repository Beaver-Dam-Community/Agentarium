-- name: LimitLockWait :exec
SET LOCAL lock_timeout = '2s';

-- name: Clock :one
SELECT statement_timestamp()::timestamptz AS now;

-- name: LockKey :exec
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(advisory_key)::text, 0));

-- name: InsertRecord :one
INSERT INTO correlation.network_policy_records
(record_id,cluster_uid,node_uid,source_epoch,source_sequence,node_name,source_time,disposition,direction,protocol,
 src_ip,src_port,dest_ip,dest_port,src_endpoint,dest_endpoint,policies,count,normalization_version)
VALUES(sqlc.arg(record_id)::uuid,sqlc.arg(cluster_uid)::uuid,sqlc.arg(node_uid)::uuid,sqlc.arg(source_epoch)::text,
 sqlc.arg(source_sequence)::bigint,sqlc.arg(node_name)::text,sqlc.arg(source_time)::timestamptz,
 sqlc.arg(disposition)::text,sqlc.arg(direction)::text,sqlc.arg(protocol)::text,
 sqlc.arg(src_ip)::inet,sqlc.narg(src_port)::integer,sqlc.arg(dest_ip)::inet,sqlc.narg(dest_port)::integer,
 sqlc.narg(src_endpoint)::jsonb,sqlc.narg(dest_endpoint)::jsonb,sqlc.narg(policies)::jsonb,
 sqlc.arg(count)::integer,sqlc.arg(normalization_version)::text)
ON CONFLICT (node_uid,source_epoch,source_sequence) DO NOTHING
RETURNING record_id;

-- name: RecordAt :one
-- The stored record for a resent sequence and whether its content is the same.
SELECT record_id,(source_time=sqlc.arg(source_time)::timestamptz AND disposition=sqlc.arg(disposition)::text
 AND direction=sqlc.arg(direction)::text AND protocol=sqlc.arg(protocol)::text AND src_ip=sqlc.arg(src_ip)::inet
 AND src_port IS NOT DISTINCT FROM sqlc.narg(src_port)::integer AND dest_ip=sqlc.arg(dest_ip)::inet
 AND dest_port IS NOT DISTINCT FROM sqlc.narg(dest_port)::integer
 AND src_endpoint IS NOT DISTINCT FROM sqlc.narg(src_endpoint)::jsonb AND dest_endpoint IS NOT DISTINCT FROM sqlc.narg(dest_endpoint)::jsonb
 AND policies IS NOT DISTINCT FROM sqlc.narg(policies)::jsonb AND count=sqlc.arg(count)::integer
 AND normalization_version=sqlc.arg(normalization_version)::text AND cluster_uid=sqlc.arg(cluster_uid)::uuid
 AND node_name=sqlc.arg(node_name)::text)::boolean AS same
FROM correlation.network_policy_records
WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text AND source_sequence=sqlc.arg(source_sequence)::bigint;

-- name: EpochsContiguous :one
-- Every epoch of the node is acknowledged through its highest stored sequence
-- or abandoned range.
SELECT NOT EXISTS (SELECT 1 FROM correlation.network_policy_watermarks w
 WHERE w.node_uid=sqlc.arg(node_uid)::uuid AND w.acked_through < greatest(
   (SELECT coalesce(max(r.source_sequence),0) FROM correlation.network_policy_records r WHERE r.node_uid=w.node_uid AND r.source_epoch=w.source_epoch),
   (SELECT coalesce(max(a.to_seq),0) FROM correlation.network_policy_abandoned_ranges a WHERE a.node_uid=w.node_uid AND a.source_epoch=w.source_epoch)))
AND NOT EXISTS (SELECT 1 FROM correlation.network_policy_records r WHERE r.node_uid=sqlc.arg(node_uid)::uuid
 AND NOT EXISTS (SELECT 1 FROM correlation.network_policy_watermarks w WHERE w.node_uid=r.node_uid AND w.source_epoch=r.source_epoch)) AS contiguous;

-- name: Watermark :one
SELECT * FROM correlation.network_policy_watermarks WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text;

-- name: SequencesAfter :many
SELECT source_sequence,source_time FROM correlation.network_policy_records
WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text AND source_sequence>sqlc.arg(after)::bigint
ORDER BY source_sequence;

-- name: MaxSequence :one
SELECT coalesce(max(source_sequence),0)::bigint FROM correlation.network_policy_records
WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text;

-- name: UpsertWatermark :exec
INSERT INTO correlation.network_policy_watermarks(node_uid,source_epoch,acked_through,acked_source_time,last_ack_at,final_flush_through,final_flush_caught_up_at)
VALUES(sqlc.arg(node_uid)::uuid,sqlc.arg(source_epoch)::text,sqlc.arg(acked_through)::bigint,sqlc.narg(acked_source_time)::timestamptz,statement_timestamp(),
 sqlc.narg(final_flush_through)::bigint,sqlc.narg(final_flush_caught_up_at)::timestamptz)
ON CONFLICT(node_uid,source_epoch) DO UPDATE SET acked_through=excluded.acked_through,acked_source_time=excluded.acked_source_time,
 last_ack_at=excluded.last_ack_at,
 final_flush_through=coalesce(excluded.final_flush_through,correlation.network_policy_watermarks.final_flush_through),
 final_flush_caught_up_at=coalesce(excluded.final_flush_caught_up_at,correlation.network_policy_watermarks.final_flush_caught_up_at);

-- name: OpenCollectorGaps :many
SELECT gap_id,start_at,evidence_refs FROM health.observation_gaps
WHERE stage='network_policy_log' AND source_id=sqlc.arg(source_id)::text AND reason='NETPOL_COLLECTOR_STOPPED' AND recovery_state='open'
ORDER BY start_at FOR UPDATE;

-- name: SequenceRange :one
SELECT coalesce(min(source_sequence),0)::bigint AS sequence_from,coalesce(max(source_sequence),0)::bigint AS sequence_to
FROM correlation.network_policy_records
WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text
AND source_time>=sqlc.arg(start_at)::timestamptz AND source_time<=sqlc.arg(end_at)::timestamptz;

-- name: BackfillGap :execrows
UPDATE health.observation_gaps SET end_at=sqlc.arg(end_at)::timestamptz,recovery_state='backfilled',evidence_refs=sqlc.arg(evidence_refs)::jsonb
WHERE gap_id=sqlc.arg(gap_id)::uuid AND recovery_state='open';

-- name: KernelConnects :many
-- tcp_connect events of one node; pod mapping and establishment are resolved
-- per event. tcp_new_state 1 is TCP_ESTABLISHED (COMMON KernelEvent).
SELECT k.source_event_id,k.source_time,k.boot_id,host(k.saddr) AS saddr,host(k.daddr) AS daddr,k.dport,
 (SELECT array_agg(DISTINCT li.pod_uid)::uuid[] FROM correlation.lifecycle_intervals li
   WHERE li.node_uid=k.node_uid AND li.boot_id=k.boot_id AND li.container_id=k.container_id
   AND li.started_at<=k.source_time AND (li.ended_at>k.source_time OR (li.ended_at IS NULL AND li.end_quality='open'))) AS pod_uids,
 EXISTS (SELECT 1 FROM audit.kernel_events s WHERE s.event_type='tcp_state' AND s.tcp_new_state=1
   AND s.node_uid=k.node_uid AND s.boot_id=k.boot_id AND s.sock_ptr=k.sock_ptr
   AND s.saddr=k.saddr AND s.sport=k.sport AND s.daddr=k.daddr AND s.dport=k.dport
   AND s.source_time>=k.source_time) AS established,
 EXISTS (SELECT 1 FROM correlation.correlations c WHERE c.kernel_event_id=k.source_event_id AND c.confidence='confirmed'
   AND c.revision=(SELECT max(c2.revision) FROM correlation.correlations c2 WHERE c2.kernel_event_id=k.source_event_id)) AS adapter_matched
FROM audit.kernel_events k
WHERE k.event_type='tcp_connect' AND k.node_uid=sqlc.arg(node_uid)::uuid
AND ((k.source_time>=sqlc.arg(from_time)::timestamptz AND k.source_time<=sqlc.arg(to_time)::timestamptz) OR k.source_event_id=ANY(sqlc.arg(ids)::uuid[]))
AND k.saddr IS NOT NULL AND k.daddr IS NOT NULL AND k.dport IS NOT NULL
ORDER BY k.source_time,k.source_event_id;

-- name: PodIdentity :one
SELECT namespace,pod_name FROM audit.lifecycle_events WHERE pod_uid=sqlc.arg(pod_uid)::uuid ORDER BY received_at LIMIT 1;

-- name: Records :many
SELECT r.*,
 (SELECT array_agg(DISTINCT le.pod_uid)::uuid[] FROM audit.lifecycle_events le
   JOIN correlation.lifecycle_intervals li ON li.pod_uid=le.pod_uid
   WHERE le.namespace=r.src_endpoint->>'namespace' AND le.pod_name=r.src_endpoint->>'pod_name'
   AND li.started_at<=r.source_time AND (li.ended_at>r.source_time OR (li.ended_at IS NULL AND li.end_quality='open'))) AS pod_uids
FROM correlation.network_policy_records r
WHERE r.node_uid=sqlc.arg(node_uid)::uuid
AND ((r.source_time>=sqlc.arg(from_time)::timestamptz AND r.source_time<=sqlc.arg(to_time)::timestamptz) OR r.record_id=ANY(sqlc.arg(ids)::uuid[]))
ORDER BY r.source_time,r.record_id;

-- name: NodeGaps :many
SELECT gap_id,stage,recovery_state FROM health.observation_gaps
WHERE node_uid=sqlc.arg(node_uid)::uuid AND stage IN ('kernel_sensor_export','network_policy_log')
AND start_at<=sqlc.arg(to_time)::timestamptz AND (end_at IS NULL OR end_at>=sqlc.arg(from_time)::timestamptz)
ORDER BY gap_id;

-- name: FindingsByMergeKey :many
SELECT * FROM correlation.network_findings_latest WHERE merge_key=sqlc.arg(merge_key)::text ORDER BY window_end DESC;

-- name: InsertFinding :one
INSERT INTO correlation.network_findings
(finding_id,revision,kind,outcome,network_segment,boundary_crossing,workload_id,pod_uid,node_uid,merge_key,
 kernel_event_ids,policy_record_ids,window_start,window_end,attempt_count,count_quality,confidence,
 rule_version,algorithm_version,reason,limitations)
VALUES(sqlc.arg(finding_id)::uuid,sqlc.arg(revision)::integer,sqlc.arg(kind)::text,sqlc.arg(outcome)::text,
 sqlc.arg(network_segment)::text,sqlc.arg(boundary_crossing)::text,sqlc.narg(workload_id)::text,sqlc.narg(pod_uid)::uuid,
 sqlc.narg(node_uid)::uuid,sqlc.arg(merge_key)::text,sqlc.arg(kernel_event_ids)::uuid[],sqlc.arg(policy_record_ids)::uuid[],
 sqlc.arg(window_start)::timestamptz,sqlc.arg(window_end)::timestamptz,sqlc.narg(attempt_count)::bigint,
 sqlc.arg(count_quality)::text,sqlc.arg(confidence)::text,sqlc.arg(rule_version)::text,sqlc.arg(algorithm_version)::text,
 sqlc.arg(reason)::text,sqlc.arg(limitations)::text[])
RETURNING created_at;

-- name: AppendAudit :one
SELECT audit.audit_append(sqlc.arg(event)::jsonb, ARRAY['gcs']::text[])::text AS result;

-- name: CoverageAfter :many
-- Stored records and abandoned ranges after the watermark, in sequence order.
SELECT source_sequence AS from_seq,source_sequence AS to_seq,source_time AS source_time
FROM correlation.network_policy_records
WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text AND source_sequence>sqlc.arg(after)::bigint
UNION ALL
SELECT from_seq,to_seq,NULL::timestamptz FROM correlation.network_policy_abandoned_ranges
WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text AND to_seq>sqlc.arg(after)::bigint
ORDER BY from_seq;

-- name: AbandonedAt :one
SELECT to_seq,reason,range_digest::text AS range_digest,gap_id FROM correlation.network_policy_abandoned_ranges
WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text AND from_seq=sqlc.arg(from_seq)::bigint;

-- name: RangeOverlaps :one
SELECT (EXISTS (SELECT 1 FROM correlation.network_policy_records WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text
   AND source_sequence BETWEEN sqlc.arg(from_seq)::bigint AND sqlc.arg(to_seq)::bigint)
 OR EXISTS (SELECT 1 FROM correlation.network_policy_abandoned_ranges WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text
   AND from_seq<=sqlc.arg(to_seq)::bigint AND to_seq>=sqlc.arg(from_seq)::bigint))::boolean AS overlaps;

-- name: AbandonedCovers :one
SELECT EXISTS (SELECT 1 FROM correlation.network_policy_abandoned_ranges WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text
 AND sqlc.arg(sequence)::bigint BETWEEN from_seq AND to_seq)::boolean AS covered;

-- name: InsertAbandoned :exec
INSERT INTO correlation.network_policy_abandoned_ranges(node_uid,source_epoch,from_seq,to_seq,reason,range_digest,gap_id)
VALUES(sqlc.arg(node_uid)::uuid,sqlc.arg(source_epoch)::text,sqlc.arg(from_seq)::bigint,sqlc.arg(to_seq)::bigint,
 sqlc.arg(reason)::text,sqlc.arg(range_digest)::text,sqlc.arg(gap_id)::uuid);

-- name: InsertGap :one
-- Closed (unrecoverable) netpol gaps declared by the collector batch.
INSERT INTO health.observation_gaps(gap_id,stage,reason,node_uid,boot_id,source_id,source_epoch,sequence_from,sequence_to,range_digest,
 start_at,end_at,loss_count,count_quality,evidence_refs,recovery_state,created_by)
VALUES(gen_random_uuid(),'network_policy_log',sqlc.arg(reason)::text,sqlc.arg(node_uid)::uuid,sqlc.narg(boot_id)::text,
 'netpol-node/'||sqlc.arg(node_uid)::uuid::text,sqlc.arg(source_epoch)::text,sqlc.narg(sequence_from)::bigint,sqlc.narg(sequence_to)::bigint,
 sqlc.narg(range_digest)::text,sqlc.arg(start_at)::timestamptz,sqlc.arg(end_at)::timestamptz,sqlc.narg(loss_count)::bigint,
 sqlc.arg(count_quality)::text,sqlc.arg(evidence_refs)::jsonb,'unrecoverable','TASK-10')
RETURNING gap_id;

-- name: NodeAckedSourceTime :one
SELECT max(acked_source_time)::timestamptz AS acked_source_time FROM correlation.network_policy_watermarks WHERE node_uid=sqlc.arg(node_uid)::uuid;

-- name: FirstLease :one
SELECT min(first_reported_at)::timestamptz AS first_reported_at FROM health.control_health_leases WHERE source_id=sqlc.arg(source_id)::text;

-- name: RotationLossAt :one
SELECT gap_id FROM correlation.network_policy_rotation_losses
WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_epoch=sqlc.arg(source_epoch)::text AND after_sequence=sqlc.arg(after_sequence)::bigint;

-- name: InsertRotationLoss :exec
INSERT INTO correlation.network_policy_rotation_losses(node_uid,source_epoch,after_sequence,detected_at,gap_id)
VALUES(sqlc.arg(node_uid)::uuid,sqlc.arg(source_epoch)::text,sqlc.arg(after_sequence)::bigint,sqlc.arg(detected_at)::timestamptz,sqlc.arg(gap_id)::uuid);

-- name: RecordsSince :one
SELECT EXISTS (SELECT 1 FROM correlation.network_policy_records WHERE node_uid=sqlc.arg(node_uid)::uuid AND source_time>sqlc.arg(since)::timestamptz)::boolean AS read;

-- name: CloseGap :execrows
UPDATE health.observation_gaps SET end_at=sqlc.arg(end_at)::timestamptz,recovery_state=sqlc.arg(recovery_state)::text,evidence_refs=sqlc.arg(evidence_refs)::jsonb
WHERE gap_id=sqlc.arg(gap_id)::uuid AND recovery_state='open';
