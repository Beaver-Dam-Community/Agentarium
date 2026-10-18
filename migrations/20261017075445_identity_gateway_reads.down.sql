DO $$
BEGIN
    IF to_regclass('adapter.adapter_executions') IS NOT NULL THEN
        REVOKE SELECT ON adapter.adapter_executions, adapter.action_results, adapter.workload_data_state FROM gateway_app;
        REVOKE USAGE ON SCHEMA adapter FROM gateway_app;
    END IF;
    IF to_regprocedure('coordinator.bind_activation_probe_action(uuid, text, uuid)') IS NOT NULL THEN
        REVOKE EXECUTE ON FUNCTION coordinator.bind_activation_probe_action(uuid, text, uuid) FROM gateway_app;
    END IF;
END
$$;

REVOKE SELECT ON
    coordinator.reservations,
    coordinator.attempts,
    coordinator.activation_probes
FROM gateway_app;
REVOKE USAGE ON SCHEMA coordinator FROM gateway_app;

REVOKE SELECT ON
    identity.issued_certificates,
    identity.registered_workloads,
    identity.session_tokens,
    identity.sessions,
    identity.service_sessions,
    identity.approvals
FROM gateway_app;
REVOKE USAGE ON SCHEMA identity FROM gateway_app;
