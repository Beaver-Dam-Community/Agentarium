-- TASK-03 objects the TASK-04 gateway reads (M2-6, gateway service PR).
--
-- migrations/README: a GRANT on another Task's schema goes in the migration
-- of the Task that owns the granted object, so the identity and coordinator
-- (TASK-03) grants for gateway_app are here.
--
-- What the gateway reads:
--   * identity.issued_certificates, identity.registered_workloads: the
--     caller's client certificate (serial, SAN, revocation) and workload role
--     (TASK-04 3.1 caller authentication).
--   * identity.session_tokens, identity.sessions, identity.service_sessions:
--     token lookup by SHA-256 digest and the verified_session input.
--   * identity.approvals: approval_snapshot.
--   * coordinator.reservations: :reevaluate refuses a reserved action.
--   * coordinator.attempts: execution_state of GET /v1/actions/{action_id}.
--   * coordinator.activation_probes: the activation_probe input.
--
-- SPEC-QUESTION: COMMON "read access to other Task tables" names this reader
-- gateway_reader and does not list identity.registered_workloads; TASK-04 chapter 4
-- names gateway_app and requires the registered_workloads principal check for
-- service callers. These grants go to gateway_app, the role that
-- 20261016181826_gateway_decisions created.

GRANT USAGE ON SCHEMA identity TO gateway_app;
GRANT SELECT ON
    identity.issued_certificates,
    identity.registered_workloads,
    identity.session_tokens,
    identity.sessions,
    identity.service_sessions,
    identity.approvals
TO gateway_app;

GRANT USAGE ON SCHEMA coordinator TO gateway_app;
GRANT SELECT ON
    coordinator.reservations,
    coordinator.attempts,
    coordinator.activation_probes
TO gateway_app;

-- Objects whose own "IF role exists" grants may have run before gateway_app
-- existed: the TASK-05 adapter tables the gateway reads (#45,
-- 20261016110000_adapter_results, which runs before
-- 20261016181826_gateway_decisions; COMMON gateway_reader list) and
-- coordinator.bind_activation_probe_action (TASK-03 C2). C2 now runs after
-- gateway_decisions and grants it itself; this block keeps the grant when C2
-- is present on a database migrated in another order. Granted here when the
-- objects exist.
DO $$
BEGIN
    IF to_regprocedure('coordinator.bind_activation_probe_action(uuid, text, uuid)') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION coordinator.bind_activation_probe_action(uuid, text, uuid) TO gateway_app;
    END IF;
    IF to_regclass('adapter.adapter_executions') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA adapter TO gateway_app;
        GRANT SELECT ON adapter.adapter_executions, adapter.action_results, adapter.workload_data_state TO gateway_app;
    END IF;
END
$$;
