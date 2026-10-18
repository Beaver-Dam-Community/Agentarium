-- TASK-10 3.6 watch history gap receiver (#109, #178). The writer never
-- inserts gaps directly: health.record_watch_gap (health_owner definer) sets
-- every server-fixed value itself, requires a non-null scope and request
-- digest, checks the installed watcher scope allowlist and is idempotent on
-- the producer gap_id. Other gap writers leave scope/request_digest NULL.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_watch_gap_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
ALTER TABLE health.observation_gaps ADD COLUMN scope text, ADD COLUMN request_digest char(64),
  ADD CONSTRAINT observation_gaps_request_pair CHECK ((scope IS NULL) = (request_digest IS NULL)),
  ADD CONSTRAINT observation_gaps_request_digest_hex CHECK (request_digest IS NULL OR request_digest ~ '^[0-9a-f]{64}$');
-- Installer-seeded pod-watcher scope allowlist; runtime has no write access.
CREATE TABLE health.watcher_scopes (scope text PRIMARY KEY CHECK (scope <> '' AND length(scope) <= 256));
REVOKE ALL ON health.watcher_scopes FROM PUBLIC;
CREATE FUNCTION health.record_watch_gap(p_gap_id uuid, p_scope text, p_source_epoch text, p_start_at timestamptz,
  p_end_at timestamptz, p_evidence_refs jsonb, p_request_digest text)
RETURNS TABLE(created boolean, request_digest text, created_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, health, pg_temp AS $$
DECLARE r record;
BEGIN
  IF p_gap_id IS NULL OR p_scope IS NULL OR p_request_digest IS NULL OR p_request_digest !~ '^[0-9a-f]{64}$'
     OR p_source_epoch IS NULL OR p_source_epoch = '' OR p_start_at IS NULL OR p_end_at IS NULL OR p_start_at > p_end_at
     OR p_evidence_refs IS NULL OR jsonb_typeof(p_evidence_refs) <> 'array' THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM health.watcher_scopes w WHERE w.scope = p_scope) THEN
    RAISE EXCEPTION 'watcher scope not allowed' USING ERRCODE = '42501';
  END IF;
  INSERT INTO health.observation_gaps(gap_id, stage, reason, source_id, source_epoch, start_at, end_at, loss_count,
    count_quality, evidence_refs, recovery_state, created_by, scope, request_digest)
  VALUES (p_gap_id, 'lifecycle_capture', 'WATCH_HISTORY_EXPIRED', 'spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher',
    p_source_epoch, p_start_at, p_end_at, NULL, 'unknown', p_evidence_refs, 'unrecoverable', 'TASK-10', p_scope, p_request_digest)
  ON CONFLICT (gap_id) DO NOTHING
  RETURNING health.observation_gaps.created_at INTO r;
  IF FOUND THEN
    RETURN QUERY SELECT true, p_request_digest, r.created_at;
    RETURN;
  END IF;
  RETURN QUERY SELECT false, coalesce(g.request_digest::text, ''), g.created_at FROM health.observation_gaps g WHERE g.gap_id = p_gap_id;
END $$;
REVOKE ALL ON FUNCTION health.record_watch_gap(uuid, text, text, timestamptz, timestamptz, jsonb, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION health.record_watch_gap(uuid, text, text, timestamptz, timestamptz, jsonb, text) TO control_health_writer;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_watch_gap_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
