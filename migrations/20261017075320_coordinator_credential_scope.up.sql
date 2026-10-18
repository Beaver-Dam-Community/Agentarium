-- TASK-03 3.2 (M2-5): view coordinator.attempt_credential_scope for the
-- TASK-06 credential broker (COMMON DB function, view and identifier registration).
--
-- Order: this migration runs after the TASK-04 decisions schema
-- (*_gateway_decisions, decisions.actions) and the TASK-06 broker_reader role
-- (*_broker_credential_bindings). It fails when either is missing; the grants
-- below are unconditional, so a missing role is never skipped silently.
--
-- Columns (attempt_id, adapter_id, operation_id, state, adapter_namespace,
-- adapter_ksa): one row per (attempt_id, adapter_namespace, adapter_ksa) for
-- every enabled registered workload whose role is adapter and whose
-- adapter_id equals the attempt's. The broker matches the caller SAN's ns/sa
-- against the two adapter columns, and the operation against
-- broker.credential_bindings.operation_id. action_id is used only for the
-- join. A disabled registration, a changed role or a changed adapter_id is
-- visible on the next query because the view reads the tables directly.
--
-- Owner rights: security_invoker = false, so the view reads the base tables
-- with the rights of its owner, the migration user that created and owns
-- coordinator.*, decisions.* and identity.* (the same user runs every
-- migration). broker_reader gets only coordinator USAGE and SELECT on the
-- view; it gets no identity USAGE and no SELECT on attempts, reservations,
-- actions or registered_workloads. security_barrier keeps the broker's own
-- predicates from running before the view's filters.
CREATE VIEW coordinator.attempt_credential_scope
WITH (security_invoker = false, security_barrier = true) AS
    SELECT a.attempt_id, a.adapter_id, action.operation_id, a.state,
           w.namespace AS adapter_namespace, w.ksa AS adapter_ksa
    FROM coordinator.attempts a
    JOIN coordinator.reservations r USING (reservation_id)
    JOIN decisions.actions action ON action.action_id = r.action_id
    JOIN identity.registered_workloads w ON w.adapter_id = a.adapter_id
        AND w.role = 'adapter' AND w.enabled;

REVOKE ALL ON coordinator.attempt_credential_scope FROM PUBLIC;
GRANT USAGE ON SCHEMA coordinator TO broker_reader;
GRANT SELECT ON coordinator.attempt_credential_scope TO broker_reader;
