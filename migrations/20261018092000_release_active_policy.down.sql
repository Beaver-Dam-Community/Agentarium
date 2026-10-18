DROP FUNCTION release.lock_active_policy(text);
REVOKE SELECT ON release.desired_bundle FROM identity_app, gateway_reader, adapter_reader, coordinator_reader, control_health_writer;
DROP TABLE release.active_policy;
DROP FUNCTION release.active_policy_epoch_guard();
REVOKE USAGE ON SCHEMA release FROM identity_app, coordinator_app, coordinator_reader, gateway_reader, adapter_reader, control_health_writer;
