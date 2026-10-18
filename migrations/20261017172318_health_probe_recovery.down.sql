BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_recovery_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
REVOKE UPDATE (released_at, release_ref) ON health.holds FROM control_health_writer;
DROP TABLE health.probe_evidence_uses;
REVOKE INSERT ON health.probe_results FROM control_health_writer;
-- Refuses (NOT NULL violation) while node-less probe rows exist; history is
-- never deleted by rollback.
DROP INDEX health.probe_results_scope;
ALTER TABLE health.probe_results
  DROP CONSTRAINT probe_results_kind_fields,
  DROP CONSTRAINT probe_results_scope_check,
  ALTER COLUMN node_uid SET NOT NULL,
  ALTER COLUMN boot_id SET NOT NULL,
  ALTER COLUMN namespace SET NOT NULL,
  ALTER COLUMN stimulus_at SET NOT NULL,
  DROP COLUMN scope,
  DROP COLUMN scope_id;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_recovery_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
