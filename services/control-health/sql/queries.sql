-- name: Clock :one
SELECT statement_timestamp()::timestamptz AS now;

-- name: Certificate :one
SELECT i.node_uid,i.boot_id,i.namespace,i.ksa,i.pod_uid FROM identity.issued_certificates i
JOIN identity.registered_workloads w ON w.namespace=i.namespace AND w.ksa=i.ksa
WHERE i.serial=sqlc.arg(serial)::text AND i.san_uri=sqlc.arg(san)::text
AND i.revoked_at IS NULL AND w.enabled AND i.issued_at<=statement_timestamp() AND i.expires_at>statement_timestamp();

-- name: Principal :one
SELECT * FROM health.component_principals WHERE principal_san=$1;

-- name: CurrentNodes :many
-- Two rows are enough to reject ambiguous current-boot history. Never choose
-- the latest timestamp as proof that the other non-retired boot is obsolete.
SELECT * FROM health.node_boot_generation WHERE node_uid=$1 AND state<>'retired' ORDER BY boot_id LIMIT 2;

-- name: ExistingLease :one
SELECT * FROM health.control_health_leases WHERE source_id=$1 AND component=$2 FOR UPDATE;

-- name: PutLease :execrows
INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,active_version,active_bundle_revision,sensor_generation,observed_state,details,lease_until,reported_at,loaded_artifact_digest,first_reported_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$13)
ON CONFLICT(source_id,component) DO UPDATE SET scope=excluded.scope,scope_id=excluded.scope_id,node_uid=excluded.node_uid,boot_id=excluded.boot_id,
loaded_artifact_digest=excluded.loaded_artifact_digest,active_version=excluded.active_version,active_bundle_revision=excluded.active_bundle_revision,sensor_generation=excluded.sensor_generation,
observed_state=excluded.observed_state,details=excluded.details,lease_until=excluded.lease_until,reported_at=excluded.reported_at
WHERE health.control_health_leases.reported_at<excluded.reported_at
AND health.control_health_leases.details->>'principal_san'=excluded.details->>'principal_san'
AND health.control_health_leases.scope=excluded.scope AND health.control_health_leases.scope_id=excluded.scope_id;

-- name: ScopeLeases :many
SELECT * FROM health.control_health_leases WHERE scope=$1 AND scope_id=$2 ORDER BY component,source_id;

-- name: ScopeHolds :many
SELECT * FROM health.holds WHERE scope=$1 AND scope_id=$2 AND released_at IS NULL ORDER BY created_at,hold_id;

-- name: NodeProbes :many
SELECT * FROM health.probe_results WHERE node_uid=$1 AND boot_id=$2 ORDER BY probe_kind,judged_at DESC;

-- name: NodeGaps :many
SELECT gap_id,stage,start_at FROM health.observation_gaps WHERE node_uid=$1 AND boot_id=$2 AND recovery_state='open' ORDER BY start_at,gap_id;

-- name: AppendAudit :one
SELECT audit.audit_append(sqlc.arg(event)::jsonb,ARRAY['gcs'])::text AS result;

-- name: ExpiredLeases :many
SELECT * FROM health.control_health_leases WHERE lease_until<=statement_timestamp() AND component<>'netpol-collector' ORDER BY source_id,component FOR UPDATE;

-- name: ExpiryHold :one
INSERT INTO health.holds(hold_id,scope,scope_id,reason,owner_component,requested_by)
VALUES(gen_random_uuid(),$1,$2,'lease_expired','control-health',$3)
ON CONFLICT(scope,scope_id,reason) WHERE released_at IS NULL DO NOTHING
RETURNING hold_id,created_at;

-- name: SetNodeBootstrapLockTimeout :exec
SELECT pg_catalog.set_config('lock_timeout', '2s', true);

-- name: LockNodeBootstrap :exec
SELECT pg_advisory_xact_lock(hashtextextended('health.node_boot_generation:' || sqlc.arg(node_uid)::text, 0));

-- name: NodeBootHistory :many
SELECT * FROM health.node_boot_generation WHERE node_uid=$1 ORDER BY boot_id;

-- name: RetireNodeBoots :exec
UPDATE health.node_boot_generation SET state='retired',updated_at=statement_timestamp()
WHERE node_uid=$1 AND state<>'retired';

-- name: InsertPreparingNodeBoot :one
INSERT INTO health.node_boot_generation(node_uid,boot_id,startup_capture,startup_capture_measurement,state,updated_at)
VALUES($1,$2,$3,$4,'preparing',statement_timestamp()) RETURNING *;

-- name: HasBootLeases :one
SELECT EXISTS(SELECT 1 FROM health.control_health_leases WHERE node_uid=$1 AND boot_id=$2);

-- name: InsertProbeResult :one
-- stimulus_at is the wire value for answer probe passes (else NULL);
-- missing_events stays empty and result is the reported outcome.
INSERT INTO health.probe_results(probe_result_id,scope,scope_id,node_uid,boot_id,namespace,probe_kind,stimulus_at,judged_at,result,evidence_refs)
VALUES(gen_random_uuid(),sqlc.arg(scope)::text,sqlc.arg(scope_id)::text,sqlc.narg(node_uid)::uuid,sqlc.narg(boot_id)::text,sqlc.narg(namespace)::text,sqlc.arg(probe_kind)::text,sqlc.narg(stimulus_at)::timestamptz,statement_timestamp(),sqlc.arg(result)::text,sqlc.arg(evidence_refs)::jsonb)
RETURNING probe_result_id,judged_at;

-- name: ScopeProbes :many
SELECT * FROM health.probe_results WHERE scope=$1 AND scope_id=$2 ORDER BY probe_kind,judged_at DESC;

-- name: SetNodeReady :execrows
-- Never mark ready while any node hold is open, even if one appeared after the
-- caller evaluated probes.
UPDATE health.node_boot_generation g SET state='ready',updated_at=statement_timestamp()
WHERE g.node_uid=sqlc.arg(node_uid) AND g.boot_id=sqlc.arg(boot_id)::text AND g.state<>'retired'
AND NOT EXISTS (SELECT 1 FROM health.holds h WHERE h.scope='node' AND h.scope_id=g.node_uid::text AND h.released_at IS NULL);

-- name: ExpiredLeaseNodes :many
SELECT DISTINCT node_uid::text AS node_uid FROM health.control_health_leases
WHERE scope='node' AND node_uid IS NOT NULL AND lease_until<=statement_timestamp() AND component<>'netpol-collector'
ORDER BY 1;

-- name: ProbeFailedHold :one
INSERT INTO health.holds(hold_id,scope,scope_id,reason,owner_component,requested_by)
VALUES(gen_random_uuid(),'node',$1,'probe_failed','control-health',$2)
ON CONFLICT(scope,scope_id,reason) WHERE released_at IS NULL DO NOTHING
RETURNING hold_id;

-- name: LockHold :one
SELECT * FROM health.holds WHERE hold_id=$1 FOR UPDATE;

-- name: OpenAutoNodeHolds :many
SELECT * FROM health.holds WHERE scope='node' AND released_at IS NULL
AND owner_component='control-health' AND reason IN ('probe_failed','lease_expired')
ORDER BY created_at,hold_id;

-- name: HoldScope :one
-- scope/scope_id are immutable; read them to take the node lock before the row lock.
SELECT scope,scope_id FROM health.holds WHERE hold_id=$1;

-- name: ReleaseHold :one
UPDATE health.holds SET released_at=statement_timestamp(),release_ref=sqlc.arg(release_ref)::text
WHERE hold_id=sqlc.arg(hold_id) AND released_at IS NULL
RETURNING released_at;

-- name: SetNodeState :execrows
UPDATE health.node_boot_generation SET state=sqlc.arg(state)::text,updated_at=statement_timestamp()
WHERE node_uid=sqlc.arg(node_uid) AND boot_id=sqlc.arg(boot_id)::text AND state<>'retired';

-- name: PodContainers :many
-- Containers of the probe runner's certified Pod open at the stimulus time.
SELECT DISTINCT container_id FROM correlation.lifecycle_intervals
WHERE pod_uid=sqlc.arg(pod_uid)::uuid AND node_uid=sqlc.arg(node_uid)::uuid AND boot_id=sqlc.arg(boot_id)::text
AND started_at<=sqlc.arg(at)::timestamptz AND (ended_at>sqlc.arg(at)::timestamptz OR (ended_at IS NULL AND end_quality='open'))
ORDER BY container_id LIMIT 17;

-- name: ProbeEvidence :many
SELECT source_event_id::uuid AS source_event_id,event_type::text AS event_type,source_time::timestamptz AS source_time,
 coalesce(host(saddr),'')::text AS saddr,coalesce(sport,0)::integer AS sport,coalesce(host(daddr),'')::text AS daddr,
 coalesce(dport,0)::integer AS dport,coalesce(tcp_new_state,0)::smallint AS tcp_new_state,coalesce(return_value,-9223372036854775808)::bigint AS return_value
FROM audit.probe_evidence_events(sqlc.arg(node_uid)::uuid,sqlc.arg(boot_id)::text,sqlc.arg(container_ids)::text[],
 sqlc.arg(from_time)::timestamptz,sqlc.arg(to_time)::timestamptz);

-- name: OtherReleaseWithRef :one
SELECT EXISTS(SELECT 1 FROM health.holds WHERE release_ref=sqlc.arg(release_ref)::text AND hold_id<>sqlc.arg(hold_id)::uuid);

-- name: ConsumeProbeEvidence :execrows
INSERT INTO health.probe_evidence_uses(kernel_event_id,probe_result_id)
VALUES(sqlc.arg(kernel_event_id)::uuid,sqlc.arg(probe_result_id)::uuid)
ON CONFLICT (kernel_event_id) DO NOTHING;

-- name: ConsumedProbeEvidence :many
SELECT kernel_event_id FROM health.probe_evidence_uses WHERE kernel_event_id=ANY(sqlc.arg(ids)::uuid[]);

-- name: RecordWatchGap :one
-- health.record_watch_gap (definer) fixes every server value and enforces the
-- installed scope allowlist; the writer has no direct INSERT on gaps.
SELECT created::boolean AS created,request_digest::text AS request_digest,created_at::timestamptz AS created_at
FROM health.record_watch_gap(sqlc.arg(gap_id)::uuid,sqlc.arg(scope)::text,sqlc.arg(source_epoch)::text,
 sqlc.arg(start_at)::timestamptz,sqlc.arg(end_at)::timestamptz,sqlc.arg(evidence_refs)::jsonb,sqlc.arg(request_digest)::text);

-- name: ExpiredNetpolLeases :many
-- One row per node: its latest netpol-collector lease, only when that lease
-- has expired and no collector of the node is still live. A node whose
-- watermark was acknowledged after the lease ended is still delivering and
-- is skipped (lease report may lag the batch by one heartbeat).
SELECT DISTINCT ON (l.node_uid) l.* FROM health.control_health_leases l
WHERE l.component='netpol-collector' AND l.scope='node' AND l.node_uid IS NOT NULL
AND NOT EXISTS (SELECT 1 FROM health.control_health_leases live WHERE live.component='netpol-collector'
  AND live.node_uid=l.node_uid AND live.lease_until>statement_timestamp())
ORDER BY l.node_uid, l.lease_until DESC, l.source_id;

-- name: NetpolAckedAfter :one
-- Still delivering: a batch was acknowledged after the lease ended and that
-- acknowledgement is recent (one heartbeat TTL plus 5s), so a stale late ack
-- never suppresses the gap forever.
SELECT EXISTS(SELECT 1 FROM correlation.network_policy_watermarks
WHERE node_uid=sqlc.arg(node_uid)::uuid AND last_ack_at>sqlc.arg(lease_until)::timestamptz
AND last_ack_at>statement_timestamp()-interval '20 seconds');

-- name: NetpolConservativeStart :one
-- With no acknowledged record: the earliest first lease of any collector of
-- the node since its latest ack (all collectors when nothing was acked).
SELECT min(l.first_reported_at)::timestamptz FROM health.control_health_leases l
WHERE l.component='netpol-collector' AND l.node_uid=sqlc.arg(node_uid)::uuid
AND l.lease_until>=coalesce((SELECT max(w.last_ack_at) FROM correlation.network_policy_watermarks w WHERE w.node_uid=l.node_uid),'-infinity'::timestamptz);

-- name: NetpolAckState :one
-- Latest epoch of the node (by last ack) decides whether a final flush ended it.
SELECT max(acked_source_time)::timestamptz AS acked_source_time,
 (SELECT w.final_flush_caught_up_at FROM correlation.network_policy_watermarks w
   WHERE w.node_uid=sqlc.arg(node_uid)::uuid ORDER BY w.last_ack_at DESC LIMIT 1)::timestamptz AS final_flush_caught_up_at
FROM correlation.network_policy_watermarks WHERE node_uid=sqlc.arg(node_uid)::uuid;

-- name: OpenNetpolCollectorGap :one
-- health.record_netpol_collector_gap (definer) fixes stage, reason, source_id,
-- count_quality, recovery_state and created_by; NULL means already open.
SELECT health.record_netpol_collector_gap(sqlc.arg(node_uid)::uuid,sqlc.narg(boot_id)::text,sqlc.arg(start_at)::timestamptz,sqlc.arg(evidence_refs)::jsonb)::uuid AS gap_id;

-- name: CreateHold :one
INSERT INTO health.holds(hold_id,scope,scope_id,reason,reason_detail,owner_component,requested_by)
VALUES(gen_random_uuid(),$1,$2,$3,sqlc.narg(reason_detail)::text,$4,$5)
ON CONFLICT(scope,scope_id,reason) WHERE released_at IS NULL DO NOTHING
RETURNING hold_id;

-- name: OpenHold :one
SELECT hold_id FROM health.holds
WHERE scope=$1 AND scope_id=$2 AND reason=$3 AND released_at IS NULL;

-- name: CurrentNodeForHold :many
SELECT * FROM health.node_boot_generation
WHERE node_uid=$1 AND state<>'retired' ORDER BY boot_id;

-- name: MarkNodeHeld :execrows
UPDATE health.node_boot_generation SET state='held',updated_at=statement_timestamp()
WHERE node_uid=$1 AND boot_id=$2 AND state<>'retired';

-- name: OwnedOpenHolds :many
-- Open holds owned by the component whose reason it may release (#177).
SELECT * FROM health.holds WHERE released_at IS NULL AND owner_component=sqlc.arg(owner_component)::text
AND reason=ANY(sqlc.arg(reasons)::text[]) ORDER BY created_at,hold_id;
