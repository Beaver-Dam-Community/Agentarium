-- Refuses while received watch gaps exist; their idempotency evidence stays.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_watch_gap_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM health.observation_gaps WHERE request_digest IS NOT NULL) THEN
  RAISE EXCEPTION 'received watch history gaps exist; refusing to drop their digests' USING ERRCODE='55000';
 END IF;
END $$;
DROP FUNCTION health.record_watch_gap(uuid, text, text, timestamptz, timestamptz, jsonb, text);
DROP TABLE health.watcher_scopes;
ALTER TABLE health.observation_gaps DROP CONSTRAINT observation_gaps_request_digest_hex,
  DROP CONSTRAINT observation_gaps_request_pair, DROP COLUMN request_digest, DROP COLUMN scope;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_watch_gap_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
