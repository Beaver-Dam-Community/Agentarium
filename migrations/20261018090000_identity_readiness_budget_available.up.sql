-- TASK-03 3.3 work-start gate: budget_available of
-- identity.work_readiness_session_view follows the TASK-03 rule.
--
-- Resolves the SPEC-QUESTION in 20261014144500_identity_workload_pki.up.sql.
-- TASK-03 decides it (work-start gate paragraph): session_budgets rows are
-- created only for sessions covered by a standing rule, so a session without
-- rows has no budget limit and budget_available is true. When rows exist it is
-- true only if at least one row is unexpired (expires_at > statement_timestamp())
-- and unexhausted (used_actions < max_actions).
--
-- CREATE OR REPLACE VIEW keeps the column names, types and order, the owner and
-- the existing GRANT SELECT to control_health_writer. The view has no
-- reloptions (security_barrier / security_invoker), before or after.

CREATE OR REPLACE VIEW identity.work_readiness_session_view AS
SELECT
    s.session_id,
    s.tenant,
    s.claimed_workload_identity,
    s.workload_id,
    s.state,
    s.expires_at,
    s.allowed_operation_ids,
    (
        NOT EXISTS (
            SELECT 1
            FROM identity.session_budgets b
            WHERE b.session_id = s.session_id
        )
        OR EXISTS (
            SELECT 1
            FROM identity.session_budgets b
            WHERE b.session_id = s.session_id
              AND b.used_actions < b.max_actions
              AND b.expires_at > statement_timestamp()
        )
    ) AS budget_available
FROM identity.sessions s;
