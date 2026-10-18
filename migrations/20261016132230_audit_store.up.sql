-- TASK-07 M1-3. Roles are groups; IAM login membership and source grants
-- are installation inputs. No producer is enabled by default.
BEGIN;
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='audit_owner') THEN CREATE ROLE audit_owner NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='audit_producer') THEN CREATE ROLE audit_producer NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='audit_writer') THEN CREATE ROLE audit_writer NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='audit_exporter') THEN CREATE ROLE audit_exporter NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='gateway_app') THEN CREATE ROLE gateway_app NOLOGIN; END IF;
  -- PostgreSQL 16+ CREATEROLE does not imply inherited or SET privileges.
  IF NOT (pg_has_role(current_user, 'audit_owner', 'USAGE') AND pg_has_role(current_user, 'audit_owner', 'SET')) THEN
    GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
    PERFORM set_config('audit_migration.granted_owner', 'on', true);
  END IF;
END $$;
CREATE SCHEMA audit AUTHORIZATION audit_owner;
SET ROLE audit_owner;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE audit.event_types (            -- COMMON event_type registry, loaded by migration
  event_type text PRIMARY KEY,
  producer_task text NOT NULL,
  storage_table text NOT NULL CHECK (storage_table IN ('audit_events','kernel_events','lifecycle_events')),
  source_class text NOT NULL CHECK (source_class IN ('business','kernel','lifecycle')),
  required_payload_fields jsonb NOT NULL
);
CREATE TABLE audit.db_role_sources (         -- session_user → allowed source
  db_role name PRIMARY KEY,
  source_id text,                            -- required when proxy=false
  proxy boolean NOT NULL DEFAULT false,      -- true only for audit_writer
  CHECK (proxy OR source_id IS NOT NULL)
);
CREATE TABLE audit.producer_event_grants (   -- event_types and tenants a source may record
  source_id text NOT NULL,
  event_type text NOT NULL REFERENCES audit.event_types(event_type),
  tenant text NOT NULL,                      -- '*' means any tenant (kernel, lifecycle)
  PRIMARY KEY (source_id, event_type, tenant)
);

CREATE TABLE audit.audit_events (
  event_id uuid PRIMARY KEY,
  event_type text NOT NULL REFERENCES audit.event_types(event_type),
  tenant text NOT NULL,
  source_id text NOT NULL,
  source_version text NOT NULL,
  source_epoch text NOT NULL,
  source_sequence bigint CHECK (source_sequence >= 1),
  source_time timestamptz NOT NULL,
  received_at timestamptz NOT NULL,
  schema_version integer NOT NULL CHECK (schema_version = 1),
  authenticated_actor text,
  workload_id text,
  session_id uuid,
  action_id uuid,
  request_id uuid,
  attempt_id uuid,
  policy_bundle_id text,
  policy_epoch bigint,
  catalog_digest char(64),
  catalog_version text,
  payload_digest char(64) NOT NULL,
  evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
  safe_payload jsonb NOT NULL
);
CREATE UNIQUE INDEX audit_events_source_seq
  ON audit.audit_events (source_id, source_epoch, source_sequence) WHERE source_sequence IS NOT NULL;
CREATE INDEX audit_events_action ON audit.audit_events (action_id, received_at);
CREATE INDEX audit_events_feed ON audit.audit_events (event_type, received_at, event_id);

CREATE TABLE audit.kernel_events (           -- COMMON KernelEvent. INSERT only
  source_event_id uuid PRIMARY KEY,
  source_id text NOT NULL,                   -- exporter mTLS identity
  sensor_id text NOT NULL,
  source_epoch text NOT NULL,
  source_sequence bigint NOT NULL CHECK (source_sequence >= 1),
  exporter_instance_id text NOT NULL,
  sensor_generation bigint NOT NULL,
  node_uid uuid NOT NULL,
  boot_id text NOT NULL,
  source_time timestamptz NOT NULL,
  spooled_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL,
  event_type text NOT NULL,                  -- process_exec, process_exit, tcp_connect, tcp_state, file_open, openat
  process_exec_id text NOT NULL,
  parent_exec_id text,
  process_start timestamptz,
  host_pid integer CHECK (host_pid > 0),   -- required to match process_exec against the session worker witness
  container_id text,
  docker_id_prefix text,
  pod_uid uuid,
  netns_inode bigint,
  saddr inet, sport integer, daddr inet, dport integer,   -- socket_tuple. only when observed
  sock_ptr bigint,                           -- KprobeSock cookie (kernel pointer). secondary key
  tcp_new_state smallint,
  lifecycle_record_id uuid,
  metadata_status text NOT NULL,
  normalization_version text NOT NULL,
  upstream_event_ref text,
  rule_hash char(64) NOT NULL,
  coverage text NOT NULL,
  safe_attributes jsonb NOT NULL,
  record_digest char(64) NOT NULL,
  UNIQUE (source_id, source_epoch, source_sequence)
);
CREATE INDEX kernel_events_tuple
  ON audit.kernel_events (netns_inode, saddr, sport, daddr, dport, source_time)
  WHERE saddr IS NOT NULL;
CREATE INDEX kernel_events_container ON audit.kernel_events (container_id, source_time);
CREATE INDEX kernel_events_exec ON audit.kernel_events (process_exec_id);
CREATE INDEX kernel_events_sock ON audit.kernel_events (node_uid, boot_id, sock_ptr, source_time)
  WHERE sock_ptr IS NOT NULL;

CREATE TABLE audit.lifecycle_events (        -- COMMON LifecycleRecord. INSERT only
  lifecycle_event_id uuid PRIMARY KEY,
  source_id text NOT NULL,
  source_kind text NOT NULL CHECK (source_kind IN ('runtime','pod_watcher')),
  source_epoch text NOT NULL,
  source_sequence bigint NOT NULL CHECK (source_sequence >= 1),
  cluster_uid uuid NOT NULL,
  pod_uid uuid NOT NULL,
  namespace text NOT NULL,
  pod_name text NOT NULL,
  node_uid uuid,
  boot_id text,
  container_id text,
  cgroups_path text,
  cgroup_inode bigint,
  container_name text,
  restart_instance integer,
  image_id text,
  image_manifest_digest text,
  transition text NOT NULL,
  source_time timestamptz,
  received_at timestamptz NOT NULL,
  resource_version text,
  mapping_version integer NOT NULL,
  evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
  missing_reason text,
  record_digest char(64) NOT NULL,
  UNIQUE (source_id, source_epoch, source_sequence)
);
CREATE INDEX lifecycle_events_pod ON audit.lifecycle_events (pod_uid, received_at);
CREATE INDEX lifecycle_events_container ON audit.lifecycle_events (container_id);

CREATE TABLE audit.ingest_watermarks (       -- contiguous ack point per epoch
  source_id text NOT NULL,
  stream text NOT NULL CHECK (stream IN ('kernel','lifecycle')),
  source_epoch text NOT NULL,
  acked_through bigint NOT NULL DEFAULT 0,   -- 1..acked_through are all stored or abandoned
  max_seen bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (source_id, stream, source_epoch)
);
CREATE TABLE audit.abandoned_ranges (        -- received sequence_range_abandoned records
  source_id text NOT NULL,
  stream text NOT NULL,
  source_epoch text NOT NULL,
  from_seq bigint NOT NULL,
  to_seq bigint NOT NULL CHECK (to_seq >= from_seq),
  reason text NOT NULL,
  range_digest char(64) NOT NULL,
  gap_id uuid NOT NULL,                      -- health.observation_gaps(TASK-10)
  received_at timestamptz NOT NULL,
  PRIMARY KEY (source_id, stream, source_epoch, from_seq)
);
CREATE TABLE audit.watch_checkpoints (       -- committed cursor of the Pod watcher
  source_id text NOT NULL,
  scope text NOT NULL,                       -- e.g. namespace/agent-exec
  resource_version text NOT NULL,            -- opaque
  lifecycle_event_id uuid NOT NULL REFERENCES audit.lifecycle_events(lifecycle_event_id),
  committed_at timestamptz NOT NULL,
  PRIMARY KEY (source_id, scope)
);

CREATE TABLE audit.audit_outbox (
  record_kind text NOT NULL CHECK (record_kind IN ('audit_event','kernel_event','lifecycle_event','decision_input')),
  record_id text NOT NULL,                   -- uuid string or decision_input_digest
  destination text NOT NULL CHECK (destination IN ('gcs','gcs_decision_inputs')),
  source_class text NOT NULL CHECK (source_class IN ('business','kernel','lifecycle','decision_input')),
  record_bytes integer NOT NULL CHECK (record_bytes > 0),   -- used to compute the backlog size limit
  state text NOT NULL CHECK (state IN ('pending','claimed','acked')),
  attempts integer NOT NULL DEFAULT 0,
  lease_until timestamptz,
  next_retry_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  ack_ref text,
  enqueued_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (record_kind, record_id, destination),
  CHECK ((destination = 'gcs_decision_inputs') = (record_kind = 'decision_input'))
);
CREATE INDEX audit_outbox_pending ON audit.audit_outbox (source_class, state, next_retry_at);

CREATE TABLE audit.export_batches (          -- GCS only. members are fixed before upload
  batch_id uuid PRIMARY KEY,
  destination text NOT NULL CHECK (destination IN ('gcs','gcs_decision_inputs')),
  source_class text NOT NULL,
  object_key text NOT NULL,
  UNIQUE (destination, object_key),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
CREATE TABLE audit.export_batch_members (
  batch_id uuid NOT NULL REFERENCES audit.export_batches(batch_id),
  ordinal integer NOT NULL,
  record_kind text NOT NULL,
  record_id text NOT NULL,
  destination text NOT NULL CHECK (destination IN ('gcs','gcs_decision_inputs')),
  PRIMARY KEY (batch_id, ordinal),
  UNIQUE (record_kind, record_id, destination),   -- a record belongs to exactly one batch
  FOREIGN KEY (record_kind, record_id, destination)
    REFERENCES audit.audit_outbox(record_kind, record_id, destination)
);
CREATE TABLE audit.manifest_intents (        -- fixes manifest order before signing. one chain per bucket
  chain_id text NOT NULL CHECK (chain_id IN ('gcs','gcs_decision_inputs')),
  manifest_seq bigint NOT NULL CHECK (manifest_seq >= 1),
  batch_id uuid NOT NULL UNIQUE REFERENCES audit.export_batches(batch_id),
  PRIMARY KEY (chain_id, manifest_seq),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
CREATE TABLE audit.export_manifests (
  chain_id text NOT NULL,
  manifest_seq bigint NOT NULL,
  PRIMARY KEY (chain_id, manifest_seq),
  FOREIGN KEY (chain_id, manifest_seq) REFERENCES audit.manifest_intents(chain_id, manifest_seq),
  object_generation bigint NOT NULL,
  batch_digest char(64) NOT NULL,
  prev_manifest_digest char(64),             -- null only for the first manifest
  manifest_digest char(64) NOT NULL,
  kms_key_version text NOT NULL,
  signature bytea NOT NULL,
  manifest_object_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  UNIQUE (chain_id, manifest_object_key)
);
CREATE TABLE audit.chain_anchors (           -- chain verification anchor after the 30-day expiry
  chain_id text NOT NULL,
  anchor_date date NOT NULL,
  manifest_seq bigint NOT NULL,
  PRIMARY KEY (chain_id, anchor_date),
  FOREIGN KEY (chain_id, manifest_seq) REFERENCES audit.export_manifests(chain_id, manifest_seq),
  manifest_digest char(64) NOT NULL,
  anchor_object_key text NOT NULL UNIQUE     -- stored in the summary bucket (90 days)
);
CREATE TABLE audit.event_conflicts (         -- written only by audit_record_conflict(), in a separate transaction
  conflict_id uuid PRIMARY KEY,
  record_kind text NOT NULL,
  record_id text NOT NULL,
  existing_digest char(64) NOT NULL,
  rejected_digest char(64) NOT NULL,
  source_id text NOT NULL,
  detected_at timestamptz NOT NULL
);
-- Snapshot of COMMON event_type registry. No source permissions are inferred.
INSERT INTO audit.event_types VALUES
('contract_created','TASK-03','audit_events','business','["action_id", "contract_digest", "displayed_contract_digest", "contract_version"]'),
('approval_requested','TASK-04','audit_events','business','["action_id", "decision_id", "reason_codes"]'),
('approval_granted','TASK-03','audit_events','business','["approval_id", "revision", "action_id", "displayed_contract_digest", "policy_epoch", "acknowledged_findings"]'),
('approval_revoked','TASK-03','audit_events','business','["approval_id", "revoke_reason"]'),
('request_received','TASK-04','audit_events','business','["action_id", "request_id", "session_id", "operation_id", "client_request_key_digest"]'),
('policy_decided','TASK-04','audit_events','business','["decision_id", "decision_stage", "verdict", "reason_codes", "matched_rule_ids", "evaluated_rule_ids", "gateway_added_rule_ids", "policy_bundle_id", "policy_epoch", "catalog_digest"]'),
('preflight_passed','TASK-05','audit_events','business','["action_id", "decision_id", "wire_body_digest", "catalog_digest"]'),
('preflight_rejected','TASK-05','audit_events','business','["action_id", "decision_id", "reason_codes", "compared_fields"]'),
('attempt_planned','TASK-03','audit_events','business','["attempt_id", "reservation_id", "action_digest", "policy_epoch"]'),
('dispatch_started','TASK-05','audit_events','business','["attempt_id", "peer_addr", "peer_port", "send_started_at"]'),
('response_received','TASK-05','audit_events','business','["attempt_id", "status_code", "response_at"]'),
('attempt_uncertain','TASK-05, TASK-03 sweeper(`OUTCOME_TIMEOUT`)','audit_events','business','["attempt_id", "stage", "reason_codes"]'),
('destination_observed','TASK-08','audit_events','business','["action_id", "action_key", "wire_body_digest", "bytes", "effect_count"]'),
('alignment_checked','TASK-11','audit_events','business','["action_id", "alignment", "evidence_level", "reducer_version", "compared_fields"]'),
('execution_held','TASK-10','audit_events','business','["hold_id", "scope", "scope_id", "reason", "owner_component"]'),
('source_health_changed','TASK-10','audit_events','business','["source_id", "scope", "from_state", "to_state", "lease_until"]'),
('evidence_gap_detected','TASK-10','audit_events','business','["gap_id", "stage", "affected_scope"]'),
('evidence_gap_resolved','TASK-10','audit_events','business','["gap_id", "recovery_state", "evidence_refs"]'),
('kernel_event_observed','TASK-09(수신 TASK-07)','kernel_events','kernel','["source_event_id", "source_epoch", "source_sequence", "process_exec_id", "event_type"]'),
('kernel_correlation_checked','TASK-10','audit_events','business','["correlation_id", "kernel_event_id", "confidence", "algorithm_version", "revision"]'),
('network_finding_recorded','TASK-10','audit_events','business','["finding_id", "revision", "kind", "outcome", "network_segment", "boundary_crossing", "confidence", "rule_version", "algorithm_version"]'),
('control_drift_detected','TASK-10','audit_events','business','["baseline_kind", "expected_digest", "observed_digest", "scope"]'),
('policy_proposed','TASK-12','audit_events','business','["proposal_id", "issue_id", "candidate_digest", "base_bundle_digest", "state"]'),
('policy_tested','TASK-13','audit_events','business','["run_id", "run_kind", "candidate_digest", "baseline_bundle_digest", "fixture_set_digest", "report_digest", "state", "release_eligible"]'),
('policy_change_approved','TASK-14','audit_events','business','["change_id", "approval_digest", "approved_by_actor", "widening_acknowledged_items", "expires_at"]'),
('policy_deployed','TASK-14','audit_events','business','["change_id", "bundle_id", "artifact_digest", "target_components"]'),
('policy_activation_verified','TASK-14','audit_events','business','["change_id", "policy_epoch", "component_acks"]'),
('policy_reverified','TASK-14','audit_events','business','["change_id", "probe_action_ids", "outcome"]'),
('policy_rolled_back','TASK-14','audit_events','business','["change_id", "from_epoch", "to_epoch", "reason"]'),
('session_created','TASK-03','audit_events','business','["session_id", "workload_id", "task_statement_digest", "claim_expires_at"]'),
('session_claimed','TASK-03','audit_events','business','["session_id", "workload_identity"]'),
('work_readiness_requested','TASK-10','audit_events','business','["check_id", "work_run_id", "checkpoint", "session_id", "workload_id", "worker_instance_id", "worker_binding_id", "instance_binding", "sensor_generation", "policy_epoch", "reason_codes", "evidence_refs"]'),
('work_readiness_passed','TASK-10','audit_events','business','["check_id", "work_run_id", "checkpoint", "session_id", "workload_id", "worker_instance_id", "worker_binding_id", "instance_binding", "sensor_generation", "policy_epoch", "reason_codes", "evidence_refs"]'),
('work_readiness_blocked','TASK-10','audit_events','business','["check_id", "work_run_id", "checkpoint", "session_id", "workload_id", "worker_instance_id", "worker_binding_id", "instance_binding", "sensor_generation", "policy_epoch", "reason_codes", "evidence_refs"]'),
('session_worker_registered','TASK-10(등록 입력 TASK-15, 독립 관측 TASK-09)','audit_events','business','["worker_binding_id", "worker_instance_id", "session_id", "runtime_process_epoch", "state", "evidence_refs", "reason_codes"]'),
('session_worker_observed','TASK-10(등록 입력 TASK-15, 독립 관측 TASK-09)','audit_events','business','["worker_binding_id", "worker_instance_id", "session_id", "runtime_process_epoch", "state", "evidence_refs", "reason_codes"]'),
('session_worker_closed','TASK-10(등록 입력 TASK-15, 독립 관측 TASK-09)','audit_events','business','["worker_binding_id", "worker_instance_id", "session_id", "runtime_process_epoch", "state", "evidence_refs", "reason_codes"]'),
('session_worker_invalidated','TASK-10(등록 입력 TASK-15, 독립 관측 TASK-09)','audit_events','business','["worker_binding_id", "worker_instance_id", "session_id", "runtime_process_epoch", "state", "evidence_refs", "reason_codes"]'),
('agent_work_start_requested','TASK-15(신뢰 runner 보고, 수신 TASK-07)','audit_events','business','["work_run_id", "session_id", "check_id", "runtime_process_epoch", "worker_instance_id", "worker_binding_id"]'),
('agent_work_started','TASK-15(신뢰 runner 보고, 수신 TASK-07)','audit_events','business','["work_run_id", "session_id", "check_id", "runtime_process_epoch", "worker_instance_id", "worker_binding_id"]'),
('agent_work_paused','TASK-15(신뢰 runner 보고, 수신 TASK-07)','audit_events','business','["work_run_id", "session_id", "check_id", "runtime_process_epoch", "worker_instance_id", "worker_binding_id"]'),
('agent_work_finished','TASK-15(신뢰 runner 보고, 수신 TASK-07)','audit_events','business','["work_run_id", "session_id", "check_id", "runtime_process_epoch", "worker_instance_id", "worker_binding_id"]'),
('service_session_created','TASK-03','audit_events','business','["service_session_id", "caller_principal", "tool_budget"]'),
('action_reevaluated','TASK-04','audit_events','business','["action_id", "previous_decision_id", "decision_id", "policy_epoch"]'),
('intent_checked','TASK-04','audit_events','business','["intent_check_id", "action_id", "model_id", "prompt_template_digest", "contract_digest", "findings_digest", "intent_check_status"]'),
('attempt_failed','TASK-05','audit_events','business','["attempt_id", "stage", "reason_codes"]'),
('attempt_released','TASK-03','audit_events','business','["attempt_id", "reservation_id", "reason_codes", "budget_restored", "released_by"]'),
('unknown_resolved','TASK-11','audit_events','business','["action_id", "attempt_id", "resolution", "evidence_refs", "resolved_by_actor"]'),
('observation_gap_recorded','TASK-07(abandoned 구간), TASK-10(그 밖)','audit_events','business','["gap_id", "stage", "reason", "count_quality"]'),
('sequence_range_abandoned','TASK-09','audit_events','business','["source_epoch", "range", "reason", "range_digest"]'),
('hold_requested','요청자(TASK-07/09/11/14 등)','audit_events','business','["scope", "scope_id", "reason", "requester", "evidence_refs"]'),
('hold_released','TASK-10(소유 구성요소 또는 운영자 승인)','audit_events','business','["hold_id", "release_ref", "released_by"]'),
('issue_created','TASK-12','audit_events','business','["issue_id", "source"]'),
('activation_probe_registered','TASK-03(호출자 TASK-14)','audit_events','business','["activation_probe_id", "change_id", "service_session_id", "client_request_key", "target_epoch"]'),
('start_permit_issued','TASK-10(start coordinator), `start_observed`는 TASK-10이 센서 증거로 확정','audit_events','business','["start_attempt_id", "binding_digest"]'),
('start_permit_consumed','TASK-10(start coordinator), `start_observed`는 TASK-10이 센서 증거로 확정','audit_events','business','["start_attempt_id", "binding_digest"]'),
('start_requested','TASK-10(start coordinator), `start_observed`는 TASK-10이 센서 증거로 확정','audit_events','business','["start_attempt_id", "binding_digest"]'),
('runtime_start_returned','TASK-10(start coordinator), `start_observed`는 TASK-10이 센서 증거로 확정','audit_events','business','["start_attempt_id", "binding_digest"]'),
('start_observed','TASK-10(start coordinator), `start_observed`는 TASK-10이 센서 증거로 확정','audit_events','business','["start_attempt_id", "binding_digest"]'),
('start_failed','TASK-10(start coordinator), `start_observed`는 TASK-10이 센서 증거로 확정','audit_events','business','["start_attempt_id", "binding_digest"]'),
('start_unknown','TASK-10(start coordinator), `start_observed`는 TASK-10이 센서 증거로 확정','audit_events','business','["start_attempt_id", "binding_digest"]'),
('start_guard_bypass_detected','TASK-10','audit_events','business','["container_id", "pod_uid", "exec_event_ref", "reason"]'),
('discovery_candidate_recorded','TASK-02','audit_events','business','["candidate_id", "library", "library_version", "call_site", "model_run_ref"]'),
('discovery_candidate_promoted','TASK-02','audit_events','business','["candidate_id", "promotion_kind", "reviewed_by_actor"]'),
('decision_replayed','TASK-13','audit_events','business','["run_id", "baseline_bundle_digest", "candidate_digest", "replayed_count", "changed_count", "replay_digest"]'),
('permission_widening_checked','TASK-14','audit_events','business','["change_id", "candidate_digest", "widened", "items_digest"]'),
('lifecycle_recorded','TASK-09(수신 TASK-07)','lifecycle_events','lifecycle','["lifecycle_event_id", "source_epoch", "source_sequence", "pod_uid", "transition"]'),
('request_rejected','TASK-04','audit_events','business','["request_id", "reason_codes"]'),
('policy_evaluation_failed','TASK-04','audit_events','business','["request_id", "reason_codes", "expected_revision"]'),
('policy_bundle_loaded','TASK-04, TASK-05','audit_events','business','["component", "source_id", "artifact_digest"]'),
('policy_bundle_load_failed','TASK-04, TASK-05','audit_events','business','["component", "source_id", "artifact_digest"]'),
('dispatch_enqueued','TASK-04','audit_events','business','["decision_id", "adapter_id"]'),
('session_revoked','TASK-03','audit_events','business','["session_id", "authenticated_actor"]'),
('session_refreshed','TASK-03','audit_events','business','["session_id", "authenticated_actor"]'),
('intent_check_requested','TASK-04','audit_events','business','["action_id", "path"]');

-- Private helpers implement the integer-only JSON subset shared with canonical.
-- PostgreSQL jsonb ordering is not RFC 8785 ordering: sort keys by UTF-16 units.
CREATE FUNCTION audit._utf16_key(s text) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE result bytea := ''::bytea; cp integer; i integer;
BEGIN
  FOR i IN 1..char_length(s) LOOP
    cp := ascii(substr(s,i,1));
    IF cp > 65535 THEN
      cp := cp - 65536;
      result := result || decode(lpad(to_hex(55296 + cp / 1024),4,'0') || lpad(to_hex(56320 + cp % 1024),4,'0'),'hex');
    ELSE
      result := result || decode(lpad(to_hex(cp),4,'0'),'hex');
    END IF;
  END LOOP;
  RETURN result;
END $$;

CREATE FUNCTION audit._canonical_json(v jsonb, depth integer DEFAULT 0) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, audit, pg_temp AS $$
DECLARE kind text := jsonb_typeof(v); result text; n integer;
BEGIN
  IF v IS NULL THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
  IF kind IN ('object','array') AND depth >= 16 THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
  CASE kind
    WHEN 'object' THEN
      SELECT count(*) INTO n FROM jsonb_object_keys(v);
      IF n > 256 OR EXISTS (SELECT FROM jsonb_object_keys(v) k WHERE octet_length(k)>128)
         OR EXISTS (SELECT FROM jsonb_object_keys(v) k GROUP BY lower(k) HAVING count(*)>1) THEN
        RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
      END IF;
      SELECT '{' || coalesce(string_agg(to_jsonb(key)::text || ':' || audit._canonical_json(value,depth+1),',' ORDER BY audit._utf16_key(key)),'') || '}'
        INTO result FROM jsonb_each(v);
    WHEN 'array' THEN
      IF jsonb_array_length(v)>1000 THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
      SELECT '[' || coalesce(string_agg(audit._canonical_json(value,depth+1),',' ORDER BY ordinal),'') || ']'
        INTO result FROM jsonb_array_elements(v) WITH ORDINALITY a(value,ordinal);
    WHEN 'string' THEN
      IF octet_length(v #>> '{}') > 16384 THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
      result := v::text;
    WHEN 'number' THEN
      IF v::text !~ '^-?[0-9]+$' OR abs(v::text::numeric)>9007199254740991 THEN
        RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
      END IF;
      result := v::text;
    ELSE result := v::text;
  END CASE;
  RETURN result;
END $$;

CREATE FUNCTION audit._authorize_source(wanted_source text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, audit, pg_temp AS $$
DECLARE allowed audit.db_role_sources%ROWTYPE;
BEGIN
  SELECT * INTO allowed FROM audit.db_role_sources WHERE db_role=session_user;
  IF NOT FOUND OR wanted_source IS NULL OR wanted_source='' OR
     (allowed.proxy AND NOT pg_has_role(session_user,'audit_writer','MEMBER')) OR
     (NOT allowed.proxy AND allowed.source_id IS DISTINCT FROM wanted_source) THEN
    RAISE EXCEPTION 'source not allowed' USING ERRCODE='42501';
  END IF;
END $$;

CREATE FUNCTION audit.audit_append(e jsonb, outbox_destinations text[]) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, audit, pg_temp AS $$
DECLARE
  registry audit.event_types%ROWTYPE;
  previous audit.audit_events%ROWTYPE;
  new_event audit.audit_events%ROWTYPE;
  canonical_text text;
  field text;
BEGIN
  PERFORM audit._authorize_source(e->>'source_id');
  IF jsonb_typeof(e) IS DISTINCT FROM 'object' OR octet_length(e::text)>1048576 OR e ? 'received_at' THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  IF EXISTS (SELECT FROM jsonb_object_keys(e) k WHERE k <> ALL(ARRAY[
      'event_id','event_type','tenant','source_id','source_version','source_epoch','source_sequence','source_time',
      'schema_version','authenticated_actor','workload_id','session_id','action_id','request_id','attempt_id',
      'policy_bundle_id','policy_epoch','catalog_digest','catalog_version','payload_digest','evidence_refs','safe_payload'])) THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  FOREACH field IN ARRAY ARRAY['event_id','event_type','tenant','source_id','source_version','source_epoch','source_time','payload_digest'] LOOP
    IF jsonb_typeof(e->field) IS DISTINCT FROM 'string' OR e->>field='' THEN
      RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
    END IF;
  END LOOP;
  FOREACH field IN ARRAY ARRAY['authenticated_actor','workload_id','session_id','action_id','request_id','attempt_id','policy_bundle_id','catalog_digest','catalog_version'] LOOP
    IF e ? field AND jsonb_typeof(e->field) NOT IN ('string','null') THEN
      RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
    END IF;
  END LOOP;
  IF e->'schema_version' IS DISTINCT FROM '1'::jsonb OR
     jsonb_typeof(e->'evidence_refs') IS DISTINCT FROM 'array' OR
     jsonb_typeof(e->'safe_payload') IS DISTINCT FROM 'object' OR
     e->>'payload_digest' !~ '^[0-9a-f]{64}$' OR
     (e->>'catalog_digest' IS NOT NULL AND e->>'catalog_digest' !~ '^[0-9a-f]{64}$') THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  FOREACH field IN ARRAY ARRAY['source_sequence','policy_epoch'] LOOP
    IF e ? field AND jsonb_typeof(e->field) NOT IN ('number','null') THEN
      RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
    END IF;
  END LOOP;
  IF e->>'source_time' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$' THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  FOREACH field IN ARRAY ARRAY['event_id','session_id','action_id','request_id','attempt_id'] LOOP
    IF e->>field IS NOT NULL AND e->>field !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
      RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
    END IF;
  END LOOP;
  canonical_text := audit._canonical_json(e);
  IF encode(sha256(convert_to(audit._canonical_json(e - 'payload_digest'),'UTF8')),'hex') <> e->>'payload_digest' THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT * INTO registry FROM audit.event_types WHERE event_type=e->>'event_type';
  IF NOT FOUND OR registry.storage_table <> 'audit_events' THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  -- '*' is a literal tenant grant, never a wildcard for business records.
  IF NOT EXISTS (SELECT FROM audit.producer_event_grants g WHERE g.source_id=e->>'source_id'
                 AND g.event_type=e->>'event_type' AND g.tenant=e->>'tenant') THEN
    RAISE EXCEPTION 'producer not allowed' USING ERRCODE='42501';
  END IF;
  FOR field IN SELECT jsonb_array_elements_text(registry.required_payload_fields) LOOP
    IF NOT (e->'safe_payload' ? field) OR e->'safe_payload'->field='null'::jsonb THEN
      RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
    END IF;
  END LOOP;
  IF outbox_destinations IS NULL OR cardinality(outbox_destinations)<>1 OR
     outbox_destinations[1] IS DISTINCT FROM 'gcs' THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  new_event := jsonb_populate_record(NULL::audit.audit_events,e);
  new_event.received_at := statement_timestamp();
  BEGIN
    INSERT INTO audit.audit_events SELECT (new_event).* ON CONFLICT (event_id) DO NOTHING;
  EXCEPTION WHEN unique_violation THEN
    -- A different event_id reusing a sequence is invalid, not an idempotent retry.
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END;
  IF FOUND THEN
    INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state)
      VALUES ('audit_event',new_event.event_id::text,'gcs',registry.source_class,octet_length(canonical_text),'pending');
    RETURN 'created';
  END IF;
  SELECT * INTO previous FROM audit.audit_events WHERE event_id=new_event.event_id;
  IF previous.source_id IS DISTINCT FROM new_event.source_id OR previous.tenant IS DISTINCT FROM new_event.tenant THEN
    RAISE EXCEPTION 'source not allowed' USING ERRCODE='42501';
  END IF;
  RETURN CASE WHEN previous.payload_digest=new_event.payload_digest THEN 'duplicate' ELSE 'conflict' END;
END $$;

CREATE FUNCTION audit.audit_record_conflict(record_kind text, record_id text, rejected_digest char(64), source_id text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, audit, pg_temp AS $$
DECLARE existing text; existing_source text; id uuid := gen_random_uuid();
BEGIN
  PERFORM audit._authorize_source(source_id);
  IF rejected_digest IS NULL OR rejected_digest !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  CASE record_kind
    WHEN 'audit_event' THEN SELECT a.payload_digest,a.source_id INTO existing,existing_source FROM audit.audit_events a WHERE a.event_id=record_id::uuid;
    WHEN 'kernel_event' THEN SELECT k.record_digest,k.source_id INTO existing,existing_source FROM audit.kernel_events k WHERE k.source_event_id=record_id::uuid;
    WHEN 'lifecycle_event' THEN SELECT l.record_digest,l.source_id INTO existing,existing_source FROM audit.lifecycle_events l WHERE l.lifecycle_event_id=record_id::uuid;
    ELSE RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END CASE;
  IF existing IS NULL OR existing_source IS DISTINCT FROM source_id THEN
    RAISE EXCEPTION 'source not allowed' USING ERRCODE='42501';
  END IF;
  IF existing=rejected_digest THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
  INSERT INTO audit.event_conflicts VALUES(id,record_kind,record_id,existing,rejected_digest,source_id,statement_timestamp());
  RETURN id;
END $$;

-- Restricted ack contract merged in PR #52.
CREATE FUNCTION audit.audit_event_ack(event_id uuid, source_id text, tenant text) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, audit, pg_temp AS $$
DECLARE result timestamptz;
BEGIN
  PERFORM audit._authorize_source(source_id);
  IF NOT EXISTS (SELECT FROM audit.db_role_sources WHERE db_role=session_user AND proxy) THEN
    RAISE EXCEPTION 'source not allowed' USING ERRCODE='42501';
  END IF;
  SELECT a.received_at INTO result FROM audit.audit_events a
    WHERE a.event_id=audit_event_ack.event_id AND a.source_id=audit_event_ack.source_id
      AND a.tenant=audit_event_ack.tenant;
  IF result IS NULL THEN RAISE EXCEPTION 'source not allowed' USING ERRCODE='42501'; END IF;
  RETURN result;
END $$;

-- COMMON grants only gateway_app this cross-task entry point. No base-table
-- access or producer source authority is implied by this function.
CREATE FUNCTION audit.enqueue_decision_input(decision_input_digest char(64), record_bytes integer)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = audit, pg_temp
AS $$
BEGIN
  IF decision_input_digest IS NULL OR decision_input_digest::text !~ '^[0-9a-f]{64}$'
     OR record_bytes IS NULL OR record_bytes <= 0 THEN
    RAISE EXCEPTION 'invalid decision input reference' USING ERRCODE='22023';
  END IF;
  INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state)
  VALUES ('decision_input',decision_input_digest,'gcs_decision_inputs','decision_input',record_bytes,'pending')
  ON CONFLICT (record_kind,record_id,destination) DO NOTHING;
END $$;

CREATE VIEW audit.collector_feed WITH (security_barrier) AS
 SELECT event_id,event_type,tenant,action_id,attempt_id,source_time,received_at,safe_payload
 FROM audit.audit_events WHERE event_type IN
 ('preflight_passed','dispatch_started','response_received','attempt_uncertain','attempt_failed');

REVOKE ALL ON ALL TABLES IN SCHEMA audit FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA audit FROM PUBLIC;
GRANT USAGE ON SCHEMA audit TO audit_producer,audit_exporter,gateway_app;
GRANT EXECUTE ON FUNCTION audit.enqueue_decision_input(char,integer) TO gateway_app;
GRANT EXECUTE ON FUNCTION audit.audit_append(jsonb,text[]),audit.audit_record_conflict(text,text,char,text) TO audit_producer;
GRANT EXECUTE ON FUNCTION audit.audit_event_ack(uuid,text,text) TO audit_writer;
GRANT SELECT ON audit.audit_events,audit.kernel_events,audit.lifecycle_events,audit.audit_outbox TO audit_exporter;
GRANT UPDATE(state,attempts,lease_until,next_retry_at,ack_ref) ON audit.audit_outbox TO audit_exporter;
GRANT SELECT,INSERT ON audit.export_batches,audit.export_batch_members,audit.manifest_intents,audit.export_manifests,audit.chain_anchors TO audit_exporter;
RESET ROLE;
GRANT audit_producer TO audit_writer;
-- Cross-task readers and FK grants are installed once their roles exist (M1-1).

DO $$ BEGIN
  IF current_setting('audit_migration.granted_owner', true) = 'on' THEN
    REVOKE audit_owner FROM CURRENT_USER;
  END IF;
END $$;
COMMIT;
