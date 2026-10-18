-- TASK-14 active_policy (COMMON common data structures active_policy, policy
-- deployment contract; TASK-14 3.2 epoch CAS). M3-1.
--
-- One row per environment (scope_id = environment). No hold column: the
-- activation hold is a TASK-10 holds row (reason = policy_activation).
--
-- Columns beyond the COMMON tuple (scope_id, epoch, bundle_id,
-- artifact_digest, expected_opa_revision, activated_by_change_id, updated_at):
--   * bundle_digest: the candidate_digest the TASK-14 3.2 CAS compares
--     (`AND bundle_digest = :expected_current_digest`) and sets.
--   * catalog_digest: the bundle's catalog digest, which the COMMON
--     reservation transaction compares (`catalog_digest = active`). The
--     coordinator does not load bundles, so it reads this value here.
-- COMMON registers both digests (#221). The sensor digest is the approved
-- release baseline (#200); initial installation supplies the lock baseline.
--
-- Writers: the releaser's epoch CAS (rest of TASK-14). No releaser role
-- exists yet, so no write grant is made here; the first row is written by the
-- installer/owner.
-- SPEC-QUESTION: TASK-14 fixes the activation order (hold → desired_bundle →
-- lease ack → epoch CAS) and does not describe how the first epoch of a new
-- installation is created.

CREATE TABLE release.active_policy (
  scope_id               text PRIMARY KEY CHECK (scope_id <> ''),
  epoch                  bigint NOT NULL CHECK (epoch >= 1),
  bundle_id              text NOT NULL CHECK (bundle_id <> ''),
  bundle_digest          char(64) NOT NULL CHECK (bundle_digest ~ '^[0-9a-f]{64}$'),
  artifact_digest        char(64) NOT NULL CHECK (artifact_digest ~ '^[0-9a-f]{64}$'),
  expected_opa_revision  text NOT NULL CHECK (expected_opa_revision <> ''),
  catalog_digest         char(64) NOT NULL CHECK (catalog_digest ~ '^[0-9a-f]{64}$'),
  sensor_release_policies_digest char(64) NOT NULL CHECK (sensor_release_policies_digest ~ '^[0-9a-f]{64}$'),
  activated_by_change_id uuid NOT NULL,
  updated_at             timestamptz NOT NULL
);

-- epoch is monotonic and never rewound, also on rollback (COMMON epoch). An
-- UPDATE must advance it by exactly one (the CAS sets epoch = epoch + 1);
-- the row is never deleted.
CREATE FUNCTION release.active_policy_epoch_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'release.active_policy rows are never deleted';
    END IF;
    IF NEW.scope_id IS DISTINCT FROM OLD.scope_id OR NEW.epoch IS DISTINCT FROM OLD.epoch + 1 THEN
        RAISE EXCEPTION 'active_policy epoch must advance by one (old %, new %)', OLD.epoch, NEW.epoch;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER active_policy_epoch BEFORE UPDATE OR DELETE ON release.active_policy
    FOR EACH ROW EXECUTE FUNCTION release.active_policy_epoch_guard();

-- Readers (COMMON read access to other Task tables). gateway_app is the role the
-- gateway pool uses and gateway_reader the COMMON name (SPEC-QUESTION in
-- 20261016181826_gateway_decisions), so both get the read. Identity and the
-- gateway read active_policy with a plain SELECT. gateway_app already reads
-- desired_bundle (20261017075446_release_gateway_reads).
GRANT USAGE ON SCHEMA release TO identity_app, coordinator_app, coordinator_reader, gateway_reader, adapter_reader, control_health_writer;
GRANT SELECT ON release.active_policy TO identity_app, gateway_app, gateway_reader, control_health_writer;
GRANT SELECT ON release.desired_bundle TO identity_app, gateway_reader, adapter_reader, coordinator_reader, control_health_writer;

-- The reservation locks the row FOR SHARE (COMMON lock order). PostgreSQL
-- requires UPDATE privilege for FOR SHARE, and the coordinator must not be
-- able to change the epoch, so the lock goes through this SECURITY DEFINER
-- function owned by the migration owner (the same pattern as the TASK-10
-- health lock functions for coordinator_reader).
-- SPEC-QUESTION: COMMON's read table does not list active_policy for a
-- coordinator role, while the COMMON reservation transaction locks it.
CREATE FUNCTION release.lock_active_policy(p_scope_id text)
RETURNS TABLE (epoch bigint, catalog_digest char(64), expected_opa_revision text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT a.epoch, a.catalog_digest, a.expected_opa_revision
    FROM release.active_policy a
    WHERE a.scope_id = p_scope_id
    FOR SHARE
$$;
REVOKE ALL ON FUNCTION release.lock_active_policy(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION release.lock_active_policy(text) TO coordinator_app;
