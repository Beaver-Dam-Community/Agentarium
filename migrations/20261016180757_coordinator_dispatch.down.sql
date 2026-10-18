REVOKE UPDATE (state) ON identity.sessions, identity.service_sessions FROM coordinator_app;
REVOKE UPDATE (used_value) ON identity.service_session_counters, identity.issue_candidate_counters FROM coordinator_app;
REVOKE UPDATE (used_actions) ON identity.approvals, identity.session_budgets FROM coordinator_app;
REVOKE SELECT ON
    identity.sessions,
    identity.service_sessions,
    identity.service_session_counters,
    identity.issue_candidate_counters,
    identity.session_budgets,
    identity.approvals,
    identity.issued_certificates,
    identity.registered_workloads
FROM coordinator_app;
REVOKE USAGE ON SCHEMA identity FROM coordinator_app;

DROP TABLE coordinator.attempt_observations;
DROP TABLE coordinator.activation_probes;
DROP TABLE coordinator.dispatch_permits;
DROP TABLE coordinator.attempts;
DROP TABLE coordinator.reservations;
DROP SCHEMA coordinator;
-- coordinator_app is left in place: install-time memberships may refer to it.
