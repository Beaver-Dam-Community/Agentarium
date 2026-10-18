-- TASK-03 3.2 / 3.3 (M1-2): workload PKI records and the session tables that
-- TASK-10 reads through identity.work_readiness_session_view.
--
-- Scope: registered_workloads, issued_certificates, sessions, session_budgets
-- and the work-readiness view. The other TASK-03 3.2 tables (session_tokens,
-- service_sessions, approvals, coordinator.*) come with M2-5.
--
-- Roles: identity_app is owned by TASK-03 and created here as a NOLOGIN group
-- role; the Cloud SQL IAM user of KSA workload-identity is made a member of it
-- at install time (TASK-16 step 3). control_health_writer is owned by TASK-10,
-- so this migration does not create it. It fails instead of skipping the GRANT
-- when the role is missing, so the view is never left without its reader.
--
-- SPEC-QUESTION: TASK-03 3.2 says budget_available means "a startable budget
-- under the current policy". active_policy (TASK-04/14) does not exist yet, so
-- the view counts unexpired, unexhausted session_budgets rows. Rows are written
-- from the active bundle when the session is created (TASK-03 3.4).

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_health_writer') THEN
        RAISE EXCEPTION 'role control_health_writer (TASK-10) must exist before identity_workload_pki';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'identity_app') THEN
        CREATE ROLE identity_app NOLOGIN;
    END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE identity.registered_workloads (
    namespace          text NOT NULL,
    ksa                text NOT NULL,
    role               text NOT NULL CHECK (role IN ('runtime', 'adapter', 'service', 'node_bridge', 'probe')),
    adapter_id         text NULL,
    service_principal  text NULL,
    enabled            boolean NOT NULL DEFAULT true,
    PRIMARY KEY (namespace, ksa),
    CHECK ((role = 'adapter') = (adapter_id IS NOT NULL))
);

CREATE TABLE identity.issued_certificates (
    serial         text PRIMARY KEY,
    san_uri        text NOT NULL,
    namespace      text NOT NULL,
    ksa            text NOT NULL,
    pod_uid        uuid NULL,
    node_uid       uuid NULL,
    boot_id        text NULL,
    issued_at      timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz NULL,
    FOREIGN KEY (namespace, ksa) REFERENCES identity.registered_workloads
);
CREATE INDEX issued_certificates_pod ON identity.issued_certificates (pod_uid) WHERE revoked_at IS NULL;

CREATE TABLE identity.sessions (
    session_id                uuid PRIMARY KEY,
    authenticated_actor       text NOT NULL,
    tenant                    text NOT NULL,
    workload_id               text NOT NULL,            -- '<namespace>/<ksa>' of registered_workloads
    task_statement            text NOT NULL CHECK (length(task_statement) <= 4000),
    allowed_operation_ids     text[] NOT NULL,
    state                     text NOT NULL CHECK (state IN ('created', 'claimed', 'expired', 'revoked')),
    claim_code_digest         bytea NOT NULL,
    claim_expires_at          timestamptz NOT NULL,
    claimed_workload_identity text NULL,                -- SAN of the Pod certificate that claimed it
    created_at                timestamptz NOT NULL,
    expires_at                timestamptz NOT NULL,
    max_expires_at            timestamptz NOT NULL      -- created_at + 8h
);

CREATE TABLE identity.session_budgets (
    session_id        uuid NOT NULL REFERENCES identity.sessions,
    standing_rule_id  text NOT NULL,
    max_actions       integer NOT NULL CHECK (max_actions > 0),
    used_actions      integer NOT NULL DEFAULT 0 CHECK (used_actions >= 0 AND used_actions <= max_actions),
    expires_at        timestamptz NOT NULL,
    PRIMARY KEY (session_id, standing_rule_id)
);

-- TASK-03 "work start gate and session permissions": no token digest, raw token or nonce.
CREATE VIEW identity.work_readiness_session_view AS
SELECT
    s.session_id,
    s.tenant,
    s.claimed_workload_identity,
    s.workload_id,
    s.state,
    s.expires_at,
    s.allowed_operation_ids,
    EXISTS (
        SELECT 1
        FROM identity.session_budgets b
        WHERE b.session_id = s.session_id
          AND b.used_actions < b.max_actions
          AND b.expires_at > statement_timestamp()
    ) AS budget_available
FROM identity.sessions s;

GRANT USAGE ON SCHEMA identity TO identity_app;
GRANT SELECT, INSERT, UPDATE ON
    identity.registered_workloads,
    identity.issued_certificates,
    identity.sessions,
    identity.session_budgets
TO identity_app;

GRANT USAGE ON SCHEMA identity TO control_health_writer;
GRANT SELECT ON identity.work_readiness_session_view TO control_health_writer;
