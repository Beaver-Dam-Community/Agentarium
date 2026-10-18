-- TASK-10 3.2/3.6 (#99, #159): COMMON probe-results wire storage with per-kind
-- required fields, verified probe inserts and column-limited hold release.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_recovery_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
-- No writer could insert probe rows before this migration; existing rows (if
-- any were installed manually) are node answer probes and keep their node.
ALTER TABLE health.probe_results ADD COLUMN scope text, ADD COLUMN scope_id text;
UPDATE health.probe_results SET scope='node', scope_id=node_uid::text;
ALTER TABLE health.probe_results
  ALTER COLUMN scope SET NOT NULL,
  ALTER COLUMN scope_id SET NOT NULL,
  ALTER COLUMN node_uid DROP NOT NULL,
  ALTER COLUMN boot_id DROP NOT NULL,
  ALTER COLUMN namespace DROP NOT NULL,
  ALTER COLUMN stimulus_at DROP NOT NULL,   -- not in the COMMON wire; never filled with a fake time
  ADD CONSTRAINT probe_results_scope_check CHECK (scope IN ('global','node','target')),
  ADD CONSTRAINT probe_results_kind_fields CHECK (
    (probe_kind IN ('process','tcp','file') AND scope='node' AND node_uid IS NOT NULL
      AND scope_id=node_uid::text AND boot_id IS NOT NULL AND boot_id<>''
      AND namespace IN ('agent-exec','agent-adapters')) OR
    (probe_kind='export' AND namespace IS NULL AND (
      (scope='global' AND scope_id='*' AND node_uid IS NULL AND boot_id IS NULL) OR
      (scope='node' AND node_uid IS NOT NULL AND scope_id=node_uid::text AND boot_id IS NULL))) OR
    (probe_kind='receipt' AND scope='target' AND scope_id<>'' AND node_uid IS NULL
      AND boot_id IS NULL AND namespace IS NULL));
CREATE INDEX probe_results_scope ON health.probe_results (scope, scope_id, probe_kind, judged_at DESC);
GRANT INSERT ON health.probe_results TO control_health_writer;
-- Each stored kernel event backs at most one answer probe pass (#179).
CREATE TABLE health.probe_evidence_uses (
  kernel_event_id uuid PRIMARY KEY,
  probe_result_id uuid NOT NULL REFERENCES health.probe_results(probe_result_id)
);
REVOKE ALL ON health.probe_evidence_uses FROM PUBLIC;
GRANT SELECT, INSERT ON health.probe_evidence_uses TO control_health_writer;
-- Release changes only these two columns; every other hold column stays immutable.
GRANT UPDATE (released_at, release_ref) ON health.holds TO control_health_writer;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_recovery_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
