-- TASK-14 release.desired_bundle read by the TASK-04 gateway (M2-6). The
-- gateway's packages/policyloader polls this environment's row every 2 s
-- (TASK-04 3.1). The adapter and control_health_writer readers get their
-- grants with their own services.

GRANT USAGE ON SCHEMA release TO gateway_app;
GRANT SELECT ON release.desired_bundle TO gateway_app;
