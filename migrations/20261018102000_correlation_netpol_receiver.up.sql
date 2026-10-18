-- TASK-10 3.7 collector batch receiver: abandoned sequence ranges and
-- rotation-loss declarations per node epoch, the restricted certificate lookup
-- that binds the shared netpol-collector SAN to its node/boot, and the lease
-- first-report read used as the conservative rotation-loss start.
-- Requires the merged identity audit-source function and the netpol schema.
BEGIN;
CREATE TABLE correlation.network_policy_abandoned_ranges (   -- INSERT only
  node_uid uuid NOT NULL,
  source_epoch text NOT NULL,
  from_seq bigint NOT NULL CHECK (from_seq >= 1),
  to_seq bigint NOT NULL,
  reason text NOT NULL CHECK (reason <> ''),
  range_digest char(64) NOT NULL,
  gap_id uuid NOT NULL,
  received_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  CHECK (to_seq >= from_seq),
  PRIMARY KEY (node_uid, source_epoch, from_seq)
);
CREATE TABLE correlation.network_policy_rotation_losses (   -- INSERT only
  node_uid uuid NOT NULL,
  source_epoch text NOT NULL,
  after_sequence bigint NOT NULL CHECK (after_sequence >= 0),
  detected_at timestamptz NOT NULL,
  gap_id uuid NOT NULL,
  received_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (node_uid, source_epoch, after_sequence)
);
REVOKE ALL ON correlation.network_policy_abandoned_ranges, correlation.network_policy_rotation_losses FROM PUBLIC;
GRANT SELECT, INSERT ON correlation.network_policy_abandoned_ranges, correlation.network_policy_rotation_losses TO correlation_writer;

-- TASK-10 3.7: EXECUTE on the restricted identity lookup only; no identity
-- base-table privilege.
GRANT USAGE ON SCHEMA identity TO correlation_writer;
GRANT EXECUTE ON FUNCTION identity.audit_source_certificate(text,text,text) TO correlation_writer;
COMMIT;

-- The rotation-loss start without an acknowledged record is the collector's
-- first lease on the node; only that column and the source key are readable.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('correlation_receiver_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
GRANT SELECT (source_id, first_reported_at) ON health.control_health_leases TO correlation_writer;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('correlation_receiver_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
