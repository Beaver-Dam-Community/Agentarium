-- TASK-08 3.1 (M2-8): test receiver effects and receive attempts.
--
-- Scope: schema receiver, receiver_effects (partial unique index on action_key
-- for idempotent mode) and receiver_attempts. The evidence collector schema
-- (evidence.*, TASK-08 3.2) is not part of this migration.
--
-- Roles: receiver_owner, receiver_writer and receipt_reader are owned by
-- TASK-08 and created here as NOLOGIN group roles. The Cloud SQL IAM user of
-- KSA receiver is made a member of receiver_writer and receipt_reader at
-- install time (TASK-16); the receiver process switches to receipt_reader for
-- the receipt API (TASK-08 2).
--
-- SPEC-QUESTION: TASK-08 2 calls receiver_writer an "IAM DB user", but Cloud
-- SQL names IAM users after the service account e-mail, so the GRANTs below
-- treat receiver_writer as a group role like coordinator_app.
--
-- Additions to the TASK-08 3.1 DDL:
-- - receiver_attempts_effect_matches_outcome: effect_created and
--   duplicate_returned refer to an effect; key_body_conflict and
--   key_missing_rejected refer to none.
-- - Both tables are append-only. The GRANTs already keep receiver_writer and
--   receipt_reader from UPDATE, DELETE and TRUNCATE; the triggers also stop
--   the owner and superusers.
-- - The migrating role gets receiver_owner only for this transaction.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'receiver_owner') THEN
        CREATE ROLE receiver_owner NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'receiver_writer') THEN
        CREATE ROLE receiver_writer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'receipt_reader') THEN
        CREATE ROLE receipt_reader NOLOGIN;
    END IF;
    -- A non-superuser migrator (Cloud SQL) needs the owner's privileges to
    -- create objects in and hand over the owner's schema. The grant is
    -- revoked at the end of this file; receiver_migration.granted_owner
    -- remembers whether this transaction made it.
    IF NOT (pg_has_role(current_user, 'receiver_owner', 'USAGE') AND pg_has_role(current_user, 'receiver_owner', 'SET')) THEN
        EXECUTE 'GRANT receiver_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE';
        PERFORM set_config('receiver_migration.granted_owner', 'on', true);
    END IF;
END
$$;

CREATE SCHEMA receiver AUTHORIZATION receiver_owner;

CREATE TABLE receiver.receiver_effects (
    effect_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    action_key uuid,                     -- Idempotency-Key. null only for keyless submissions in non_idempotent mode
    receiver_mode text NOT NULL CHECK (receiver_mode IN ('idempotent','non_idempotent')),
    wire_body_digest char(64) NOT NULL,  -- computed by the server from the received bytes
    content_digest_server char(64),      -- computed with packages/canonical; not independent evidence
    body_bytes integer NOT NULL CHECK (body_bytes >= 0),
    client_principal text NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (receiver_mode = 'non_idempotent' OR action_key IS NOT NULL)
);
CREATE UNIQUE INDEX receiver_effects_idempotent_key
    ON receiver.receiver_effects (action_key) WHERE receiver_mode = 'idempotent';

CREATE TABLE receiver.receiver_attempts (
    receipt_attempt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),  -- server-generated
    client_attempt_id uuid,              -- X-Agentarium-Attempt-Id. not unique
    action_key uuid,
    client_principal text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    wire_body_digest char(64) NOT NULL,
    body_bytes integer NOT NULL,
    outcome text NOT NULL CHECK (outcome IN
        ('effect_created','duplicate_returned','key_body_conflict','key_missing_rejected')),
    effect_id uuid REFERENCES receiver.receiver_effects(effect_id),
    CONSTRAINT receiver_attempts_effect_matches_outcome CHECK (
        (outcome IN ('effect_created','duplicate_returned')) = (effect_id IS NOT NULL))
);
CREATE INDEX receiver_attempts_key ON receiver.receiver_attempts (action_key, received_at);
CREATE INDEX receiver_attempts_digest ON receiver.receiver_attempts (client_principal, wire_body_digest, received_at);

-- Append-only. RAISE EXCEPTION uses SQLSTATE P0001. DROP TABLE is not a
-- trigger event, so the down migration still works.
CREATE FUNCTION receiver.reject_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'receiver.% is append-only (% rejected)', TG_TABLE_NAME, TG_OP;
END
$$;
REVOKE ALL ON FUNCTION receiver.reject_change() FROM PUBLIC;

CREATE TRIGGER receiver_effects_append_only BEFORE UPDATE OR DELETE ON receiver.receiver_effects
    FOR EACH ROW EXECUTE FUNCTION receiver.reject_change();
CREATE TRIGGER receiver_effects_no_truncate BEFORE TRUNCATE ON receiver.receiver_effects
    FOR EACH STATEMENT EXECUTE FUNCTION receiver.reject_change();
CREATE TRIGGER receiver_attempts_append_only BEFORE UPDATE OR DELETE ON receiver.receiver_attempts
    FOR EACH ROW EXECUTE FUNCTION receiver.reject_change();
CREATE TRIGGER receiver_attempts_no_truncate BEFORE TRUNCATE ON receiver.receiver_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION receiver.reject_change();

ALTER TABLE receiver.receiver_effects OWNER TO receiver_owner;
ALTER TABLE receiver.receiver_attempts OWNER TO receiver_owner;
ALTER FUNCTION receiver.reject_change() OWNER TO receiver_owner;

REVOKE ALL ON ALL TABLES IN SCHEMA receiver FROM PUBLIC;
GRANT USAGE ON SCHEMA receiver TO receiver_writer, receipt_reader;
GRANT SELECT, INSERT ON receiver.receiver_effects, receiver.receiver_attempts TO receiver_writer;
GRANT SELECT ON receiver.receiver_effects, receiver.receiver_attempts TO receipt_reader;  -- receipt API read path

DO $$
BEGIN
    IF current_setting('receiver_migration.granted_owner', true) = 'on' THEN
        EXECUTE 'REVOKE receiver_owner FROM CURRENT_USER';
    END IF;
END
$$;

COMMIT;
