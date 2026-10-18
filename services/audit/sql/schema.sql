-- Query-generation signatures only. Runtime schema lives in migrations/.
CREATE SCHEMA audit;
CREATE FUNCTION audit.audit_append(e jsonb, outbox_destinations text[]) RETURNS text LANGUAGE sql AS $$ SELECT ''::text $$;
CREATE FUNCTION audit.audit_record_conflict(record_kind text, record_id text, rejected_digest char(64), source_id text) RETURNS uuid LANGUAGE sql AS $$ SELECT NULL::uuid $$;
CREATE FUNCTION audit.audit_event_ack(event_id uuid, source_id text, tenant text) RETURNS timestamptz LANGUAGE sql AS $$ SELECT NULL::timestamptz $$;
-- TASK-03 adapter surface; never creates identity tables at runtime.
CREATE SCHEMA identity;
CREATE TABLE identity.registered_workloads(namespace text,ksa text,role text,adapter_id text,service_principal text,enabled boolean);
-- Export verification subset. Runtime definitions remain in the audit migration.
CREATE TABLE audit.export_batches(batch_id uuid PRIMARY KEY,destination text,source_class text,object_key text,created_at timestamptz);
CREATE TABLE audit.export_batch_members(batch_id uuid,ordinal integer,record_kind text,record_id text,destination text);
CREATE TABLE audit.audit_outbox(record_kind text NOT NULL,record_id text NOT NULL,destination text NOT NULL,source_class text NOT NULL,record_bytes integer NOT NULL,state text NOT NULL,attempts integer NOT NULL,lease_until timestamptz,next_retry_at timestamptz NOT NULL,ack_ref text,enqueued_at timestamptz NOT NULL,outbox_id bigint NOT NULL);
CREATE TABLE audit.manifest_intents(chain_id text NOT NULL,manifest_seq bigint NOT NULL,batch_id uuid NOT NULL,created_at timestamptz NOT NULL,fencing_token bigint);
CREATE TABLE audit.export_manifests(chain_id text NOT NULL,manifest_seq bigint NOT NULL,object_generation bigint NOT NULL,batch_digest char(64) NOT NULL,prev_manifest_digest char(64),manifest_digest char(64) NOT NULL,kms_key_version text NOT NULL,signature bytea NOT NULL,manifest_object_key text NOT NULL,fencing_token bigint,created_at timestamptz NOT NULL);

CREATE TABLE audit.audit_events(event_id uuid,event_type text NOT NULL,source_id text NOT NULL,source_epoch text NOT NULL,source_sequence bigint);

CREATE TABLE audit.kernel_events(source_event_id uuid,node_uid uuid,source_id text NOT NULL,source_epoch text NOT NULL,source_sequence bigint NOT NULL);
CREATE TABLE audit.lifecycle_events(lifecycle_event_id uuid,node_uid uuid,source_id text NOT NULL,source_epoch text NOT NULL,source_sequence bigint NOT NULL);

CREATE SCHEMA decisions;
CREATE TABLE decisions.decision_inputs(decision_input_digest char(64) PRIMARY KEY,tenant text NOT NULL,sanitized_input jsonb NOT NULL,policy_bundle_id text NOT NULL,created_at timestamptz NOT NULL);


CREATE SCHEMA health;
CREATE FUNCTION identity.audit_source_certificate(certificate_serial text,exact_san text,requested_boot_hash text) RETURNS TABLE(namespace text,ksa text,node_uid uuid,certificate_boot_id text,historical_boot_id text) LANGUAGE sql AS $$ SELECT NULL::text,NULL::text,NULL::uuid,NULL::text,NULL::text $$;
CREATE FUNCTION health.audit_source_current_boot(node_uid uuid,certificate_boot_id text) RETURNS boolean LANGUAGE sql AS $$ SELECT false $$;
CREATE FUNCTION audit.ingest_lifecycle_batch(source_id text,batch jsonb,certificate_serial text,exact_san text,writer_version text,writer_epoch text) RETURNS jsonb LANGUAGE sql AS $$ SELECT NULL::jsonb $$;
CREATE FUNCTION audit.lifecycle_checkpoint(source_id text,scope text) RETURNS TABLE(scope text,resource_version text,committed_at timestamptz,checkpoint_revision bigint) LANGUAGE sql AS $$ SELECT NULL::text,NULL::text,NULL::timestamptz,NULL::bigint $$;
CREATE FUNCTION audit.ingest_kernel_batch(source_id text,batch jsonb,certificate_serial text,exact_san text,writer_version text,writer_epoch text) RETURNS jsonb LANGUAGE sql AS $$ SELECT NULL::jsonb $$;

CREATE FUNCTION audit.acquire_manifest_lease(p_chain_id text,p_holder text) RETURNS TABLE(fencing_token bigint,lease_until timestamptz) LANGUAGE sql AS $$ SELECT NULL::bigint,NULL::timestamptz $$;
CREATE FUNCTION audit.release_manifest_lease(p_chain_id text,p_holder text,p_fencing_token bigint) RETURNS boolean LANGUAGE sql AS $$ SELECT false $$;
