-- TASK-03 3.2 (M2-5): dispatch coordinator tables.
--
-- Scope: reservations, attempts, dispatch_permits, activation_probes and
-- attempt_observations (TASK-03 3.2 DDL) and the coordinator_app role. The DB
-- functions bind_activation_probe_action and resolve_unknown_attempt and view
-- attempt_credential_scope come with the second coordinator PR.
--
-- Roles: coordinator_app is owned by TASK-03 and created here as a NOLOGIN
-- group role; the Cloud SQL IAM user of the coordinator KSA is made a member
-- at install time (TASK-16). Membership in audit_producer (TASK-07) and
-- coordinator_reader (TASK-10) and the SELECT on active_policy and decisions
-- are granted where those objects are created.
--
-- SPEC-QUESTION: PostgreSQL row locks (FOR UPDATE / FOR SHARE) need UPDATE
-- privilege on at least one column of the table. The role table gives
-- coordinator_app "UPDATE (budget columns only)", but identity.sessions and
-- identity.service_sessions have no budget column, so the reservation
-- transaction could not lock them. UPDATE(state) is granted on both for the
-- lock only; the coordinator never writes it.
--
-- SPEC-QUESTION: the coordinator authenticates an adapter by the serial of
-- the certificate it presented, which needs SELECT on
-- identity.issued_certificates and identity.registered_workloads. The
-- TASK-03 role table does not list them.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coordinator_app') THEN
        CREATE ROLE coordinator_app NOLOGIN;
    END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS coordinator;

CREATE TABLE coordinator.reservations (
    reservation_id     uuid PRIMARY KEY,
    action_id          uuid NOT NULL UNIQUE,
    decision_id        uuid NOT NULL,
    action_digest      char(64) NOT NULL,
    decision_basis     text NOT NULL CHECK (decision_basis IN ('approval', 'standing_rule', 'service_scope', 'activation_probe')),
    approval_id        uuid NULL,
    approval_revision  integer NULL,
    session_id         uuid NULL,
    standing_rule_id   text NULL,
    service_session_id uuid NULL,
    budget_counter     text NULL,                    -- service_session_counters.counter
    state              text NOT NULL CHECK (state IN ('reserved', 'committed', 'released')),
    created_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL
);

CREATE TABLE coordinator.attempts (
    attempt_id       uuid PRIMARY KEY,
    action_id        uuid NOT NULL,
    reservation_id   uuid NOT NULL REFERENCES coordinator.reservations,
    adapter_id       text NOT NULL,
    adapter_node_uid uuid NOT NULL,
    state            text NOT NULL CHECK (state IN ('planned', 'claimed', 'dispatched', 'response_received', 'failed', 'unknown', 'released', 'resolved')),
    reason_codes     text[] NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL,
    claimed_at       timestamptz NULL,
    updated_at       timestamptz NOT NULL,
    resolution_id    uuid NULL
);
CREATE UNIQUE INDEX attempts_one_active_action ON coordinator.attempts (action_id)
    WHERE state IN ('planned', 'claimed', 'dispatched', 'unknown');
CREATE INDEX attempts_by_reservation ON coordinator.attempts (reservation_id);

CREATE TABLE coordinator.dispatch_permits (
    permit_id        uuid PRIMARY KEY,
    attempt_id       uuid NOT NULL UNIQUE REFERENCES coordinator.attempts,
    decision_id      uuid NOT NULL,
    action_id        uuid NOT NULL,
    adapter_id       text NOT NULL,
    action_digest    char(64) NOT NULL,
    wire_body_digest char(64) NOT NULL,
    policy_epoch     bigint NOT NULL,
    catalog_digest   char(64) NOT NULL,
    expires_at       timestamptz NOT NULL,
    claimed_at       timestamptz NULL
);
CREATE INDEX dispatch_permits_unclaimed ON coordinator.dispatch_permits (expires_at) WHERE claimed_at IS NULL;

CREATE TABLE coordinator.activation_probes (
    activation_probe_id uuid PRIMARY KEY,
    change_id           uuid NOT NULL,
    service_session_id  uuid NOT NULL REFERENCES identity.service_sessions,
    client_request_key  text NOT NULL,
    action_id           uuid NULL,                 -- filled by bind_activation_probe_action() at submission
    target_epoch        bigint NOT NULL,
    expires_at          timestamptz NOT NULL,
    UNIQUE (service_session_id, client_request_key),
    UNIQUE (action_id)
);

CREATE TABLE coordinator.attempt_observations (
    attempt_id          uuid PRIMARY KEY REFERENCES coordinator.attempts,
    local_addr          inet NULL,
    local_port          integer NULL,
    peer_addr           inet NULL,
    peer_port           integer NULL,
    netns_inode         bigint NULL,
    pod_uid             uuid NULL,
    connect_started_at  timestamptz NULL,
    send_started_at     timestamptz NULL,
    send_finished_at    timestamptz NULL,
    response_at         timestamptz NULL,
    provider_request_id text NULL,
    k8s_audit_id        text NULL,
    wire_body_digest    char(64) NULL,
    recorded_at         timestamptz NOT NULL
);
CREATE INDEX attempt_observations_tuple
    ON coordinator.attempt_observations (netns_inode, local_addr, local_port);

GRANT USAGE ON SCHEMA coordinator TO coordinator_app;
GRANT SELECT, INSERT, UPDATE ON
    coordinator.reservations,
    coordinator.attempts,
    coordinator.dispatch_permits,
    coordinator.activation_probes,
    coordinator.attempt_observations
TO coordinator_app;

GRANT USAGE ON SCHEMA identity TO coordinator_app;
GRANT SELECT ON
    identity.sessions,
    identity.service_sessions,
    identity.service_session_counters,
    identity.issue_candidate_counters,
    identity.session_budgets,
    identity.approvals,
    identity.issued_certificates,
    identity.registered_workloads
TO coordinator_app;
GRANT UPDATE (used_actions) ON identity.approvals, identity.session_budgets TO coordinator_app;
GRANT UPDATE (used_value) ON identity.service_session_counters, identity.issue_candidate_counters TO coordinator_app;
GRANT UPDATE (state) ON identity.sessions, identity.service_sessions TO coordinator_app;  -- row locks only, see above
