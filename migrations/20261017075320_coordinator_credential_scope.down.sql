-- The broker_reader role belongs to TASK-06 and is not dropped here.
REVOKE USAGE ON SCHEMA coordinator FROM broker_reader;
DROP VIEW coordinator.attempt_credential_scope;
