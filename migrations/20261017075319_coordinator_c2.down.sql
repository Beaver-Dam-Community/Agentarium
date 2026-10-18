DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
        REVOKE USAGE ON SCHEMA coordinator FROM gateway_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'timeline_app') THEN
        REVOKE USAGE ON SCHEMA coordinator FROM timeline_app;
    END IF;
END
$$;
DROP FUNCTION coordinator.resolve_unknown_attempt(uuid, uuid);
DROP FUNCTION coordinator.bind_activation_probe_action(uuid, text, uuid);
REVOKE SELECT ON identity.session_tokens FROM coordinator_app;
ALTER TABLE coordinator.attempt_observations
    DROP COLUMN peer_addr_kind,
    DROP COLUMN dialed_addr;
