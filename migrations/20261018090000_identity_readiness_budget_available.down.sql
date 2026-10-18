-- Reverts 20261018090000_identity_readiness_budget_available.up.sql: restores
-- the budget_available definition of 20261014144500_identity_workload_pki.up.sql
-- (a session without session_budgets rows is false). Owner and grants are kept.

CREATE OR REPLACE VIEW identity.work_readiness_session_view AS
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
