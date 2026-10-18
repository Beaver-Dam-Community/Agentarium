-- Query generation only; migrations and cross-task owners supply runtime schema.
CREATE SCHEMA broker;
CREATE TABLE broker.credential_bindings(credential_binding text,adapter_id text,operation_id text,secret_resource text NOT NULL,secret_version text NOT NULL,header_name text NOT NULL,header_format text NOT NULL,enabled boolean,updated_at timestamptz,updated_by text);
CREATE SCHEMA coordinator;
-- COMMON contract adapter. Does not create or replace another owner's view.
CREATE TABLE coordinator.attempt_credential_scope(attempt_id uuid,adapter_id text,operation_id text,state text,adapter_namespace text,adapter_ksa text);
