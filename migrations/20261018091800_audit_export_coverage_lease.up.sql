-- TASK-07 3.2.1 (#98/#99 owner decisions): outbox_id coverage for every
-- manifest, PostgreSQL manifest lease with a fencing token enforced inside the
-- intent/manifest INSERT transaction, the read-only audit_verifier role, the
-- export_verification_failed registry row and the audit_retention purge job.
-- Never rewrite a merged migration; this one only adds objects and columns.
BEGIN;
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_verifier') THEN CREATE ROLE audit_verifier NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_retention') THEN CREATE ROLE audit_retention NOLOGIN; END IF;
  IF NOT (pg_has_role(current_user, 'audit_owner', 'USAGE') AND pg_has_role(current_user, 'audit_owner', 'SET')) THEN
    GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
    PERFORM set_config('audit_export_lease.granted_owner', 'on', true);
  END IF;
END $$;
SET ROLE audit_owner;
SET LOCAL lock_timeout = '2s';

-- Storage order of outbox rows. Not a source sequence; existing rows receive
-- values in physical order during the rewrite and keep them afterwards.
ALTER TABLE audit.audit_outbox ADD COLUMN outbox_id bigint GENERATED ALWAYS AS IDENTITY;
ALTER TABLE audit.audit_outbox ADD CONSTRAINT audit_outbox_outbox_id_key UNIQUE (outbox_id);

CREATE TABLE audit.manifest_leases (
  chain_id text PRIMARY KEY CHECK (chain_id IN ('gcs','gcs_decision_inputs')),
  holder text CHECK (holder IS NULL OR (holder <> '' AND octet_length(holder) <= 256)),
  holder_role name,
  fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
  lease_until timestamptz,
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
INSERT INTO audit.manifest_leases(chain_id) VALUES ('gcs'), ('gcs_decision_inputs');
REVOKE ALL ON audit.manifest_leases FROM PUBLIC;

ALTER TABLE audit.manifest_intents ADD COLUMN fencing_token bigint CHECK (fencing_token >= 1);
ALTER TABLE audit.export_manifests ADD COLUMN fencing_token bigint CHECK (fencing_token >= 1);

-- Same holder renews a live lease with the same token. An empty or expired
-- lease is taken over with token + 1, also by the previous holder. A live
-- lease of another holder returns no row.
CREATE FUNCTION audit.acquire_manifest_lease(p_chain_id text, p_holder text)
RETURNS TABLE(fencing_token bigint, lease_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
AS $$
DECLARE
  l audit.manifest_leases%ROWTYPE;
  now_ts timestamptz;
BEGIN
  IF p_chain_id IS NULL OR p_chain_id NOT IN ('gcs','gcs_decision_inputs') OR p_holder IS NULL OR p_holder = '' OR octet_length(p_holder) > 256 THEN
    RAISE EXCEPTION 'invalid manifest lease request' USING ERRCODE = '22023';
  END IF;
  IF NOT pg_has_role(session_user, 'audit_exporter', 'MEMBER') THEN
    RAISE EXCEPTION 'manifest lease requires audit_exporter' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO l FROM audit.manifest_leases m WHERE m.chain_id = p_chain_id FOR UPDATE;
  now_ts := clock_timestamp();
  IF l.holder = p_holder AND l.lease_until > now_ts THEN
    UPDATE audit.manifest_leases m SET lease_until = now_ts + interval '30 seconds', updated_at = now_ts WHERE m.chain_id = p_chain_id;
    RETURN QUERY SELECT l.fencing_token, now_ts + interval '30 seconds';
  ELSIF l.lease_until IS NULL OR l.lease_until <= now_ts THEN
    UPDATE audit.manifest_leases m
       SET holder = p_holder, holder_role = session_user, fencing_token = l.fencing_token + 1,
           lease_until = now_ts + interval '30 seconds', updated_at = now_ts
     WHERE m.chain_id = p_chain_id;
    RETURN QUERY SELECT l.fencing_token + 1, now_ts + interval '30 seconds';
  END IF;
END $$;

CREATE FUNCTION audit.release_manifest_lease(p_chain_id text, p_holder text, p_fencing_token bigint)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
AS $$
BEGIN
  IF NOT pg_has_role(session_user, 'audit_exporter', 'MEMBER') THEN
    RAISE EXCEPTION 'manifest lease requires audit_exporter' USING ERRCODE = '42501';
  END IF;
  UPDATE audit.manifest_leases m SET lease_until = clock_timestamp(), updated_at = clock_timestamp()
   WHERE m.chain_id = p_chain_id AND m.holder = p_holder AND m.fencing_token = p_fencing_token AND m.lease_until > clock_timestamp();
  RETURN FOUND;
END $$;

-- Fencing: the inserting transaction keeps the lease row share-locked until it
-- ends, so a takeover waits for this commit and stale tokens are rejected.
CREATE FUNCTION audit._require_manifest_lease()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.fencing_token IS NULL THEN
    RAISE EXCEPTION 'manifest fencing token required' USING ERRCODE = 'AU401';
  END IF;
  PERFORM 1 FROM audit.manifest_leases l
   WHERE l.chain_id = NEW.chain_id AND l.fencing_token = NEW.fencing_token AND l.lease_until > clock_timestamp()
   FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'manifest lease lost or fencing token stale' USING ERRCODE = 'AU401';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER manifest_intents_fencing BEFORE INSERT ON audit.manifest_intents
  FOR EACH ROW EXECUTE FUNCTION audit._require_manifest_lease();
CREATE TRIGGER export_manifests_fencing BEFORE INSERT ON audit.export_manifests
  FOR EACH ROW EXECUTE FUNCTION audit._require_manifest_lease();

INSERT INTO audit.event_types VALUES
('export_verification_failed','TASK-07','audit_events','business','["chain_id", "manifest_seq", "failure_code"]');

-- Deletes only fully acknowledged, manifest-committed batches whose outbox rows
-- and stored records are all older than 30 days and whose manifest commit
-- (export_manifests.created_at) is older than 31 days. The verifier checks
-- manifests committed within 30 days, so verified batches keep their rows
-- however late they were exported (TASK-07 3.2.1). A batch whose record is still
-- referenced elsewhere is skipped as a whole. decisions.decision_inputs is
-- TASK-04 data and is never deleted here. Batch and manifest metadata remain.
CREATE FUNCTION audit.purge_expired_records(batch_limit integer)
RETURNS TABLE(purged_batches bigint, skipped_batches bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
AS $$
DECLARE
  b record;
  cutoff timestamptz := clock_timestamp() - interval '30 days';
  manifest_cutoff timestamptz := clock_timestamp() - interval '31 days';
  purged bigint := 0;
  skipped bigint := 0;
BEGIN
  IF batch_limit IS NULL OR batch_limit < 1 OR batch_limit > 1000 THEN
    RAISE EXCEPTION 'batch_limit outside 1..1000' USING ERRCODE = '22023';
  END IF;
  IF NOT pg_has_role(session_user, 'audit_retention', 'MEMBER') THEN
    RAISE EXCEPTION 'purge requires audit_retention' USING ERRCODE = '42501';
  END IF;
  FOR b IN
    SELECT eb.batch_id FROM audit.export_batches eb
     WHERE EXISTS (SELECT FROM audit.export_batch_members m WHERE m.batch_id = eb.batch_id)
       AND EXISTS (SELECT FROM audit.manifest_intents i JOIN audit.export_manifests em USING (chain_id, manifest_seq)
                    WHERE i.batch_id = eb.batch_id AND em.created_at < manifest_cutoff)
       AND NOT EXISTS (
         SELECT FROM audit.export_batch_members m
           JOIN audit.audit_outbox o USING (record_kind, record_id, destination)
          WHERE m.batch_id = eb.batch_id AND (o.state <> 'acked' OR o.enqueued_at >= cutoff))
       AND NOT EXISTS (
         SELECT FROM audit.export_batch_members m
          WHERE m.batch_id = eb.batch_id AND (
            (m.record_kind = 'audit_event' AND EXISTS (SELECT FROM audit.audit_events e WHERE e.event_id::text = m.record_id AND e.received_at >= cutoff)) OR
            (m.record_kind = 'kernel_event' AND EXISTS (SELECT FROM audit.kernel_events k WHERE k.source_event_id::text = m.record_id AND k.received_at >= cutoff)) OR
            (m.record_kind = 'lifecycle_event' AND EXISTS (SELECT FROM audit.lifecycle_events l WHERE l.lifecycle_event_id::text = m.record_id AND l.received_at >= cutoff))))
     ORDER BY eb.created_at, eb.batch_id
     LIMIT batch_limit
  LOOP
    BEGIN
      -- Records first (no FK from outbox to records). A record still exported
      -- to another destination keeps its row until that outbox row is purged.
      DELETE FROM audit.audit_events e USING audit.export_batch_members m
       WHERE m.batch_id = b.batch_id AND m.record_kind = 'audit_event' AND e.event_id::text = m.record_id
         AND NOT EXISTS (SELECT FROM audit.audit_outbox o WHERE o.record_kind = m.record_kind AND o.record_id = m.record_id AND o.destination <> m.destination);
      DELETE FROM audit.kernel_events k USING audit.export_batch_members m
       WHERE m.batch_id = b.batch_id AND m.record_kind = 'kernel_event' AND k.source_event_id::text = m.record_id
         AND NOT EXISTS (SELECT FROM audit.audit_outbox o WHERE o.record_kind = m.record_kind AND o.record_id = m.record_id AND o.destination <> m.destination);
      DELETE FROM audit.lifecycle_events l USING audit.export_batch_members m
       WHERE m.batch_id = b.batch_id AND m.record_kind = 'lifecycle_event' AND l.lifecycle_event_id::text = m.record_id
         AND NOT EXISTS (SELECT FROM audit.audit_outbox o WHERE o.record_kind = m.record_kind AND o.record_id = m.record_id AND o.destination <> m.destination);
      WITH d AS (DELETE FROM audit.export_batch_members m WHERE m.batch_id = b.batch_id RETURNING m.record_kind, m.record_id, m.destination)
      DELETE FROM audit.audit_outbox o USING d
       WHERE o.record_kind = d.record_kind AND o.record_id = d.record_id AND o.destination = d.destination;
      purged := purged + 1;
    EXCEPTION WHEN foreign_key_violation THEN
      skipped := skipped + 1;
    END;
  END LOOP;
  RETURN QUERY SELECT purged, skipped;
END $$;

REVOKE ALL ON FUNCTION audit.acquire_manifest_lease(text, text), audit.release_manifest_lease(text, text, bigint),
  audit._require_manifest_lease(), audit.purge_expired_records(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.acquire_manifest_lease(text, text), audit.release_manifest_lease(text, text, bigint) TO audit_exporter;
GRANT USAGE ON SCHEMA audit TO audit_verifier, audit_retention;
GRANT SELECT ON audit.export_batches, audit.export_batch_members, audit.manifest_intents, audit.export_manifests TO audit_verifier;
GRANT SELECT (record_kind, record_id, destination, state, ack_ref, outbox_id) ON audit.audit_outbox TO audit_verifier;
GRANT EXECUTE ON FUNCTION audit.purge_expired_records(integer) TO audit_retention;

RESET ROLE;
DO $$ BEGIN
  IF current_setting('audit_export_lease.granted_owner', true) = 'on' THEN
    REVOKE audit_owner FROM CURRENT_USER;
  END IF;
END $$;
COMMIT;
