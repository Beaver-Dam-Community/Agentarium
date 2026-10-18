-- TASK-03 3.4 (M2-5): session tokens, service sessions and their counters.
--
-- Builds on 20261014144500_identity_workload_pki (sessions, session_budgets).
-- approvals and approval_nonces come with the approval PR; coordinator.* with
-- the coordinator PR.

-- COMMON Session keeps requested_scope {operation_ids[], target_ids[]}.
-- operation_ids are stored as allowed_operation_ids; target_ids are kept here.
-- SPEC-QUESTION: whether the gateway enforces the requested targets is open
-- (verified_session has no target_ids).
ALTER TABLE identity.sessions
    ADD COLUMN requested_target_ids text[] NOT NULL DEFAULT '{}';

CREATE TABLE identity.service_sessions (
    service_session_id  uuid PRIMARY KEY,
    caller_principal    text NOT NULL,
    authenticated_actor text NOT NULL CHECK (authenticated_actor LIKE 'service:%'),  -- service:<namespace>/<ksa>
    profile             text NOT NULL CHECK (profile IN ('intent_check', 'policy_proposal', 'discovery', 'activation_probe')),
    tenant              text NOT NULL,
    issue_id            uuid NULL,
    candidate_id        uuid NULL,
    change_id           uuid NULL,
    snapshot_id         uuid NULL,
    action_id           uuid NULL,
    state               text NOT NULL CHECK (state IN ('active', 'expired', 'revoked')),
    created_at          timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL,
    CHECK (num_nonnulls(issue_id, change_id, snapshot_id, action_id) = 1),
    CHECK (candidate_id IS NULL OR issue_id IS NOT NULL)
);

CREATE TABLE identity.session_tokens (
    token_digest       bytea PRIMARY KEY CHECK (length(token_digest) = 32),  -- SHA-256(token)
    session_id         uuid NULL REFERENCES identity.sessions,
    service_session_id uuid NULL REFERENCES identity.service_sessions,
    bound_identity     text NOT NULL,                                        -- certificate SAN
    issued_at          timestamptz NOT NULL,
    revoked_at         timestamptz NULL,
    CHECK ((session_id IS NULL) <> (service_session_id IS NULL))
);
CREATE INDEX session_tokens_live ON identity.session_tokens (session_id) WHERE revoked_at IS NULL;

CREATE TABLE identity.service_session_counters (
    service_session_id uuid NOT NULL REFERENCES identity.service_sessions,
    counter            text NOT NULL CHECK (counter IN ('read_tools', 'model', 'snapshot_reads', 'probe_actions')),
    max_value          integer NOT NULL CHECK (max_value >= 0),
    used_value         integer NOT NULL DEFAULT 0 CHECK (used_value >= 0 AND used_value <= max_value),
    PRIMARY KEY (service_session_id, counter)
);

CREATE TABLE identity.issue_candidates (
    issue_id      uuid NOT NULL,
    candidate_id  uuid NOT NULL,
    created_at    timestamptz NOT NULL,
    PRIMARY KEY (issue_id, candidate_id)
);

-- Authoritative usage of one policy_proposal candidate, across all its
-- service sessions. Each session keeps its own maximum in
-- service_session_counters.max_value; a reservation for a session with a
-- candidate consumes here while used_value < that maximum, and a release gives
-- the use back here. service_session_counters.used_value of such a session
-- counts only the uses made through that session, so used_value here is the
-- sum of the candidate's per-session used_value.
CREATE TABLE identity.issue_candidate_counters (
    issue_id      uuid NOT NULL,
    candidate_id  uuid NOT NULL,
    counter       text NOT NULL CHECK (counter IN ('read_tools', 'model', 'snapshot_reads', 'probe_actions')),
    used_value    integer NOT NULL DEFAULT 0 CHECK (used_value >= 0),
    PRIMARY KEY (issue_id, candidate_id, counter),
    FOREIGN KEY (issue_id, candidate_id) REFERENCES identity.issue_candidates
);

GRANT SELECT, INSERT, UPDATE ON
    identity.service_sessions,
    identity.session_tokens,
    identity.service_session_counters,
    identity.issue_candidates,
    identity.issue_candidate_counters
TO identity_app;
