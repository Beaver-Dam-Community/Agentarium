-- name: AppendEvent :one
SELECT audit.audit_append(sqlc.arg(event)::jsonb, ARRAY['gcs']::text[])::text AS result;

-- name: RecordConflict :one
SELECT audit.audit_record_conflict('audit_event',sqlc.arg(event_id)::text,sqlc.arg(digest)::char(64),sqlc.arg(source_id)::text)::uuid AS conflict_id;

-- name: EventAck :one
SELECT audit.audit_event_ack(sqlc.arg(event_id)::uuid,sqlc.arg(source_id)::text,sqlc.arg(tenant)::text)::timestamptz AS received_at;

-- name: RegisteredProducer :one
SELECT EXISTS(SELECT FROM identity.registered_workloads
 WHERE namespace=sqlc.arg(namespace)::text AND ksa=sqlc.arg(ksa)::text
 AND enabled AND role IN ('service','adapter') AND service_principal=sqlc.arg(principal)::text)::boolean AS registered;

-- name: CheckBatchAck :one
SELECT count(*)::bigint AS total,
 count(*) FILTER (WHERE o.state='acked' AND o.ack_ref=sqlc.arg(ack_ref)::text)::bigint AS acknowledged
FROM audit.export_batches b
JOIN audit.export_batch_members m ON m.batch_id=b.batch_id AND m.destination=b.destination
LEFT JOIN audit.audit_outbox o ON o.record_kind=m.record_kind AND o.record_id=m.record_id AND o.destination=m.destination
WHERE b.batch_id=sqlc.arg(batch_id)::uuid AND b.destination=sqlc.arg(destination)::text
 AND b.object_key=sqlc.arg(object_key)::text;


-- name: RetryBatchCandidates :many
SELECT b.batch_id FROM audit.export_batches b
WHERE b.destination=sqlc.arg(destination)::text AND b.source_class=sqlc.arg(source_class)::text
AND EXISTS (SELECT FROM audit.export_batch_members m JOIN audit.audit_outbox o USING(record_kind,record_id,destination)
 WHERE m.batch_id=b.batch_id AND o.next_retry_at<=statement_timestamp()
 AND (o.state='pending' OR (o.state='claimed' AND o.lease_until<=statement_timestamp())))
ORDER BY b.created_at,b.batch_id LIMIT 100;

-- name: BatchInfo :one
SELECT batch_id,destination,source_class,object_key,created_at FROM audit.export_batches WHERE batch_id=$1;

-- name: BatchMemberCount :one
SELECT count(*)::bigint FROM audit.export_batch_members WHERE batch_id=$1;

-- name: LockBatchMembers :many
SELECT o.record_kind,o.record_id,o.destination,o.state,o.attempts,o.lease_until,o.outbox_id,
 (o.next_retry_at<=statement_timestamp() AND (o.state='pending' OR (o.state='claimed' AND o.lease_until<=statement_timestamp())))::boolean AS claimable,
 COALESCE(o.lease_until>statement_timestamp(),false)::boolean AS lease_live
FROM audit.export_batch_members m JOIN audit.audit_outbox o USING(record_kind,record_id,destination)
WHERE m.batch_id=$1 ORDER BY m.ordinal FOR UPDATE OF o SKIP LOCKED;

-- name: LockUnbatched :many
SELECT o.record_kind,o.record_id,o.destination,o.state,o.attempts,o.lease_until,o.outbox_id,true::boolean AS claimable,false::boolean AS lease_live
FROM audit.audit_outbox o
WHERE o.destination=sqlc.arg(destination)::text AND o.source_class=sqlc.arg(source_class)::text
AND o.state='pending' AND o.next_retry_at<=statement_timestamp()
AND NOT EXISTS (SELECT FROM audit.export_batch_members m WHERE m.record_kind=o.record_kind AND m.record_id=o.record_id AND m.destination=o.destination)
ORDER BY o.enqueued_at,o.record_kind,o.record_id LIMIT 100 FOR UPDATE OF o SKIP LOCKED;

-- name: ExportDBTime :one
SELECT statement_timestamp()::timestamptz;

-- name: CreateExportBatch :exec
INSERT INTO audit.export_batches(batch_id,destination,source_class,object_key,created_at) VALUES($1,$2,$3,$4,$5);

-- name: AddExportMember :exec
INSERT INTO audit.export_batch_members(batch_id,ordinal,record_kind,record_id,destination) VALUES($1,$2,$3,$4,$5);

-- name: ClaimOutboxMember :one
UPDATE audit.audit_outbox SET state='claimed',attempts=attempts+1,lease_until=statement_timestamp()+interval '30 seconds'
WHERE record_kind=$1 AND record_id=$2 AND destination=$3 RETURNING attempts;

-- name: RetryOutboxMember :execrows
UPDATE audit.audit_outbox SET state='pending',lease_until=NULL,next_retry_at=statement_timestamp()+make_interval(secs => sqlc.arg(delay_seconds)::integer)
WHERE record_kind=sqlc.arg(record_kind)::text AND record_id=sqlc.arg(record_id)::text AND destination=sqlc.arg(destination)::text
AND state='claimed' AND attempts=sqlc.arg(attempts)::integer AND lease_until>statement_timestamp();

-- name: AckOutboxMember :execrows
UPDATE audit.audit_outbox SET state='acked',lease_until=NULL,ack_ref=sqlc.arg(ack_ref)::text
WHERE record_kind=sqlc.arg(record_kind)::text AND record_id=sqlc.arg(record_id)::text AND destination=sqlc.arg(destination)::text
AND state='claimed' AND attempts=sqlc.arg(attempts)::integer AND lease_until>statement_timestamp();

-- name: CommittedExportManifest :one
SELECT EXISTS(SELECT FROM audit.manifest_intents i JOIN audit.export_manifests m USING(chain_id,manifest_seq)
WHERE i.batch_id=sqlc.arg(batch_id)::uuid AND i.chain_id=sqlc.arg(destination)::text
AND m.object_generation=sqlc.arg(generation)::bigint AND m.batch_digest=sqlc.arg(batch_digest)::char(64)
AND m.manifest_digest=sqlc.arg(manifest_digest)::char(64))::boolean;

-- name: ExportAuditRecord :one
SELECT to_jsonb(e)::jsonb AS record,e.event_type,e.source_id,e.source_epoch,e.source_sequence
FROM audit.audit_events e WHERE event_id=$1;


-- The session lock covers external I/O without keeping a transaction open.
-- Its connection must be discarded if unlock cannot be confirmed.
-- name: TryManifestChainLock :one
SELECT pg_try_advisory_lock(1096107076::integer,sqlc.arg(chain_key)::integer)::boolean;

-- name: ReleaseManifestChainLock :one
SELECT pg_advisory_unlock(1096107076::integer,sqlc.arg(chain_key)::integer)::boolean;

-- name: IntentForBatch :one
SELECT chain_id,manifest_seq,batch_id,created_at,fencing_token FROM audit.manifest_intents WHERE batch_id=$1;

-- name: LatestIntent :one
SELECT chain_id,manifest_seq,batch_id,created_at,fencing_token FROM audit.manifest_intents WHERE chain_id=$1 ORDER BY manifest_seq DESC LIMIT 1;

-- name: ReserveManifestIntent :one
INSERT INTO audit.manifest_intents(chain_id,manifest_seq,batch_id,fencing_token) VALUES($1,$2,$3,$4)
RETURNING chain_id,manifest_seq,batch_id,created_at,fencing_token;

-- name: ManifestForSequence :one
SELECT chain_id,manifest_seq,object_generation,batch_digest,prev_manifest_digest,manifest_digest,kms_key_version,signature,manifest_object_key
FROM audit.export_manifests WHERE chain_id=$1 AND manifest_seq=$2;

-- name: CommitExportManifest :exec
INSERT INTO audit.export_manifests(chain_id,manifest_seq,object_generation,batch_digest,prev_manifest_digest,manifest_digest,kms_key_version,signature,manifest_object_key,fencing_token)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(chain_id,manifest_seq) DO NOTHING;

-- name: ExportKernelRecord :one
SELECT to_jsonb(e)::jsonb AS record FROM audit.kernel_events e WHERE source_event_id=$1;

-- name: ExportLifecycleRecord :one
SELECT to_jsonb(e)::jsonb AS record FROM audit.lifecycle_events e WHERE lifecycle_event_id=$1;

-- name: ExportBacklogs :many
SELECT o.source_class,
 COALESCE(k.node_uid::text,l.node_uid::text,'')::text AS node_uid,
 count(*)::bigint AS pending_records,
 sum(o.record_bytes)::bigint AS pending_bytes,
 GREATEST(0,EXTRACT(EPOCH FROM (statement_timestamp()-min(o.enqueued_at))))::double precision AS oldest_age_seconds
FROM audit.audit_outbox o
LEFT JOIN audit.kernel_events k ON o.record_kind='kernel_event' AND k.source_event_id::text=o.record_id
LEFT JOIN audit.lifecycle_events l ON o.record_kind='lifecycle_event' AND l.lifecycle_event_id::text=o.record_id
WHERE o.state<>'acked'
GROUP BY o.source_class,COALESCE(k.node_uid::text,l.node_uid::text,'')
ORDER BY o.source_class,COALESCE(k.node_uid::text,l.node_uid::text,'');

-- name: ExportDecisionInput :one
SELECT jsonb_build_object('decision_input_digest',decision_input_digest,'tenant',tenant,'sanitized_input',sanitized_input,'policy_bundle_id',policy_bundle_id,'created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::jsonb AS record
FROM decisions.decision_inputs WHERE decision_input_digest=$1;

-- name: IngestLifecycleBatch :one
SELECT audit.ingest_lifecycle_batch(sqlc.arg(source_id)::text,sqlc.arg(batch)::jsonb,sqlc.arg(certificate_serial)::text,sqlc.arg(exact_san)::text,sqlc.arg(writer_version)::text,sqlc.arg(writer_epoch)::text)::jsonb AS ack;

-- name: LifecycleSourceCertificate :one
SELECT namespace::text,ksa::text,node_uid::uuid,coalesce(certificate_boot_id,'')::text AS certificate_boot_id
FROM identity.audit_source_certificate(sqlc.arg(certificate_serial)::text,sqlc.arg(exact_san)::text,NULL::text);

-- name: LifecycleCurrentBoot :one
SELECT health.audit_source_current_boot(sqlc.arg(node_uid)::uuid,sqlc.arg(boot_id)::text)::boolean AS current_boot;

-- name: LifecycleCheckpoint :one
SELECT scope::text,resource_version::text,committed_at::timestamptz,checkpoint_revision::bigint
FROM audit.lifecycle_checkpoint(sqlc.arg(source_id)::text,sqlc.arg(scope)::text);

-- name: IngestKernelBatch :one
SELECT audit.ingest_kernel_batch(sqlc.arg(source_id)::text,sqlc.arg(batch)::jsonb,sqlc.arg(certificate_serial)::text,sqlc.arg(exact_san)::text,sqlc.arg(writer_version)::text,sqlc.arg(writer_epoch)::text)::jsonb AS ack;

-- name: AcquireManifestLease :many
SELECT fencing_token::bigint AS fencing_token,lease_until::timestamptz AS lease_until
FROM audit.acquire_manifest_lease(sqlc.arg(chain_id)::text,sqlc.arg(holder)::text);

-- name: ReleaseManifestLease :one
SELECT audit.release_manifest_lease(sqlc.arg(chain_id)::text,sqlc.arg(holder)::text,sqlc.arg(fencing_token)::bigint)::boolean AS released;

-- Verifier coverage: fixed members in ordinal order with their outbox_id.
-- name: BatchCoverage :many
SELECT m.ordinal::integer AS ordinal,m.record_kind::text AS record_kind,m.record_id::text AS record_id,o.outbox_id::bigint AS outbox_id
FROM audit.export_batch_members m
JOIN audit.audit_outbox o ON o.record_kind=m.record_kind AND o.record_id=m.record_id AND o.destination=m.destination
WHERE m.batch_id=sqlc.arg(batch_id)::uuid AND m.destination=sqlc.arg(destination)::text
ORDER BY m.ordinal;

-- Verification window (TASK-07 3.2.1): the intent time is the signed
-- manifest created_at; both timestamps are DB-assigned and immutable.
-- name: ManifestTimes :one
SELECT i.created_at::timestamptz AS intent_at,
 (i.created_at < statement_timestamp() - interval '30 days')::boolean AS outside,
 m.manifest_digest::text AS manifest_digest
FROM audit.manifest_intents i JOIN audit.export_manifests m ON m.chain_id=i.chain_id AND m.manifest_seq=i.manifest_seq
WHERE i.chain_id=sqlc.arg(chain_id)::text AND i.manifest_seq=sqlc.arg(manifest_seq)::bigint;
