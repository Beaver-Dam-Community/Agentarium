-- TASK-10 M1-4. No private outbox: state transitions call TASK-07 audit_append in the same transaction.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='health_owner') THEN CREATE ROLE health_owner NOLOGIN; END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='health_reader') THEN CREATE ROLE health_reader NOLOGIN; END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='coordinator_reader') THEN CREATE ROLE coordinator_reader NOLOGIN; END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='gateway_reader') THEN CREATE ROLE gateway_reader NOLOGIN; END IF;
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_migration.granted_owner','on',true);
 END IF;
END $$;
CREATE SCHEMA health AUTHORIZATION health_owner;
SET ROLE health_owner;

-- Caller authorization is seeded by the installer, never by the runtime writer.
CREATE TABLE health.component_principals (
    principal_san           text PRIMARY KEY,
    component               text NOT NULL,                  -- COMMON ControlHealthLease.component
    allowed_scopes          text[] NOT NULL,
    allowed_hold_reasons    text[] NOT NULL,                -- reasons the caller may request
    releasable_hold_reasons text[] NOT NULL                 -- reasons the caller may auto-release
);

CREATE TABLE health.control_health_leases (
    source_id               text NOT NULL,
    component               text NOT NULL,
    scope                   text NOT NULL CHECK (scope IN ('global', 'node', 'workload', 'target', 'session')),
    scope_id                text NOT NULL,
    node_uid                uuid,
    boot_id                 text,
    active_version          text,
    loaded_artifact_digest  text,
    active_bundle_revision  text,
    sensor_generation       bigint,
    observed_state          text NOT NULL CHECK (observed_state IN ('healthy', 'degraded', 'unhealthy')),
    details                 jsonb NOT NULL DEFAULT '{}'::jsonb,   -- canonical_version, principal SAN, caller cert serial
    lease_until             timestamptz NOT NULL,
    reported_at             timestamptz NOT NULL,
    first_reported_at       timestamptz NOT NULL,
    PRIMARY KEY (source_id, component)
);
CREATE INDEX control_health_leases_scope ON health.control_health_leases (scope, scope_id);

CREATE TABLE health.holds (
    hold_id         uuid PRIMARY KEY,
    scope           text NOT NULL CHECK (scope IN ('global', 'node', 'workload', 'target', 'session')),
    scope_id        text NOT NULL,                              -- global is '*'
    reason          text NOT NULL CHECK (reason IN (
        'export_lag', 'db_unavailable', 'probe_failed', 'lease_expired', 'start_unknown', 'sensor_degraded',
        'control_drift', 'bypass_detected', 'sensor_tampering', 'alignment_mismatch', 'audit_integrity', 'risk_event',
        'policy_activation', 'operator_stop')),
    reason_detail   text,                                       -- risk_event only (COMMON hold.reason_detail)
    owner_component text NOT NULL,
    requested_by    text NOT NULL,                              -- caller SAN, or control-health for its own holds
    created_at      timestamptz NOT NULL DEFAULT statement_timestamp(),
    released_at     timestamptz,
    release_ref     text,
    CHECK ((released_at IS NULL) = (release_ref IS NULL)),
    CHECK ((reason = 'risk_event') = (reason_detail IS NOT NULL)),
    CHECK (reason_detail IS NULL OR reason_detail IN (
        'unregistered_connect_established', 'protected_path_write', 'unexpected_child_exec'))
);
CREATE UNIQUE INDEX holds_open_unique ON health.holds (scope, scope_id, reason) WHERE released_at IS NULL;
CREATE INDEX holds_open_scope ON health.holds (scope, scope_id) WHERE released_at IS NULL;

CREATE TABLE health.probe_results (
    probe_result_id uuid PRIMARY KEY,
    node_uid        uuid,
    boot_id         text,
    namespace       text,
    probe_kind      text NOT NULL CHECK (probe_kind IN ('process', 'tcp', 'file', 'export', 'receipt')),
    stimulus_at     timestamptz,
    judged_at       timestamptz NOT NULL,
    result          text NOT NULL CHECK (result IN ('pass', 'fail', 'unknown')),
    missing_events  text[] NOT NULL DEFAULT '{}',
    evidence_refs   jsonb NOT NULL DEFAULT '[]'::jsonb,
    scope           text NOT NULL,
    scope_id        text NOT NULL
);
CREATE INDEX probe_results_recent ON health.probe_results (node_uid, probe_kind, judged_at DESC);

CREATE TABLE health.observation_gaps (       -- COMMON ObservationGap. TASK-07 functions also INSERT
    gap_id              uuid PRIMARY KEY,
    stage               text NOT NULL CHECK (stage IN ('kernel_sensor_export', 'lifecycle_capture', 'network_policy_log')),
    reason              text NOT NULL,       -- COMMON ObservationGap.reason, limited per stage below
    node_uid            uuid,
    boot_id             text,
    source_id           text,
    source_epoch        text,
    sequence_from       bigint,
    sequence_to         bigint,
    range_digest        char(64),
    start_at            timestamptz NOT NULL,
    end_at              timestamptz,
    affected_workloads  text[] NOT NULL DEFAULT '{}',
    loss_count          bigint,
    count_quality       text NOT NULL CHECK (count_quality IN ('exact', 'estimated', 'unknown')),
    evidence_refs       jsonb NOT NULL DEFAULT '[]'::jsonb,
    recovery_state      text NOT NULL CHECK (recovery_state IN
        ('open', 'backfilled', 'partially_recovered', 'unrecoverable')),
    created_by          text NOT NULL,       -- 'TASK-07' or 'TASK-10'
    created_at          timestamptz NOT NULL DEFAULT statement_timestamp(),
    scope               text,
    request_digest      char(64),
    CHECK ((sequence_from IS NULL) = (sequence_to IS NULL)),
    CHECK (
        (stage = 'kernel_sensor_export' AND reason IN
            ('SEQUENCE_RANGE_ABANDONED', 'EXPORT_ROTATION_LOSS', 'NODE_LOST_BEFORE_ACK')) OR
        (stage = 'lifecycle_capture' AND reason IN
            ('SEQUENCE_RANGE_ABANDONED', 'WATCH_HISTORY_EXPIRED', 'RUNTIME_RECORD_MISSING',
             'METADATA_UNRESOLVED', 'NODE_LOST_BEFORE_ACK')) OR
        (stage = 'network_policy_log' AND reason IN
            ('SEQUENCE_RANGE_ABANDONED', 'NETPOL_COLLECTOR_STOPPED', 'NETPOL_FILE_ROTATION_LOSS',
             'NETPOL_NODE_LOG_DROPPED', 'NODE_LOST_BEFORE_ACK'))),
    CHECK (stage <> 'network_policy_log' OR recovery_state = 'open' OR end_at IS NOT NULL),
    CHECK (stage <> 'network_policy_log' OR source_id IS NOT NULL)
);
CREATE UNIQUE INDEX observation_gaps_open_netpol
    ON health.observation_gaps (stage, source_id, reason)
    WHERE stage = 'network_policy_log' AND recovery_state = 'open';
CREATE INDEX observation_gaps_node ON health.observation_gaps (node_uid, start_at);

CREATE TABLE health.node_boot_generation (
    node_uid          uuid NOT NULL,
    boot_id           text NOT NULL,
    sensor_generation bigint NOT NULL DEFAULT 1,
    guard_generation  bigint NOT NULL DEFAULT 1,
    startup_capture   text NOT NULL CHECK (startup_capture IN ('guarded', 'unsupported')),
    state             text NOT NULL CHECK (state IN ('preparing', 'ready', 'held', 'retired')),
    updated_at        timestamptz NOT NULL,
    -- Added by *_health_startup_capture_measurement; no default (#104, #189).
    startup_capture_measurement text NOT NULL CHECK (startup_capture_measurement IN ('measured', 'not_measured')),
    PRIMARY KEY (node_uid, boot_id),
    CHECK (startup_capture = 'unsupported' OR startup_capture_measurement = 'measured')
);

REVOKE ALL ON ALL TABLES IN SCHEMA health FROM PUBLIC;
GRANT USAGE ON SCHEMA health TO control_health_writer, health_reader, coordinator_reader, gateway_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA health TO control_health_writer, health_reader;
GRANT INSERT,UPDATE ON health.control_health_leases,health.node_boot_generation TO control_health_writer;
GRANT SELECT ON health.holds,health.control_health_leases,health.node_boot_generation TO coordinator_reader;
GRANT SELECT ON health.holds,health.control_health_leases TO gateway_reader;
GRANT INSERT ON health.holds TO control_health_writer;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_migration.granted_owner',true)='on' THEN
  REVOKE health_owner FROM CURRENT_USER;
 END IF;
END $$;
COMMIT;
-- TASK-07 audit_producer membership, source grants and cross-task read grants
-- are install-time prerequisites. Runtime code never creates schema or roles.

-- TASK-03 query-generation adapter only, never installed by this migration.
CREATE SCHEMA identity;
CREATE TABLE identity.issued_certificates(serial text,san_uri text,namespace text NOT NULL,ksa text NOT NULL,pod_uid uuid,node_uid uuid,boot_id text,issued_at timestamptz,expires_at timestamptz,revoked_at timestamptz);
CREATE TABLE identity.registered_workloads(namespace text NOT NULL,ksa text NOT NULL,enabled boolean);
CREATE SCHEMA audit;
CREATE FUNCTION audit.audit_append(e jsonb,destinations text[]) RETURNS text LANGUAGE sql AS $$SELECT ''::text$$;

CREATE FUNCTION audit.probe_evidence_events(p_node_uid uuid, p_boot_id text, p_container_ids text[], p_from timestamptz, p_to timestamptz)
RETURNS TABLE(source_event_id uuid, event_type text, source_time timestamptz, saddr inet, sport integer, daddr inet, dport integer, tcp_new_state smallint, return_value bigint)
LANGUAGE sql AS $$SELECT NULL::uuid,NULL::text,NULL::timestamptz,NULL::inet,NULL::integer,NULL::inet,NULL::integer,NULL::smallint,NULL::bigint$$;

CREATE SCHEMA correlation;
CREATE TABLE correlation.lifecycle_intervals (
  interval_id uuid PRIMARY KEY, cluster_uid uuid NOT NULL, pod_uid uuid NOT NULL, node_uid uuid NOT NULL, boot_id text NOT NULL,
  container_id text NOT NULL, restart_instance integer, cgroup_inode bigint, netns_inode bigint, started_at timestamptz,
  ended_at timestamptz, end_quality text NOT NULL, mapping_version integer NOT NULL, source_event_ids uuid[] NOT NULL);

CREATE TABLE health.probe_evidence_uses (
    kernel_event_id uuid PRIMARY KEY,
    probe_result_id uuid NOT NULL REFERENCES health.probe_results(probe_result_id)
);

CREATE FUNCTION health.record_watch_gap(p_gap_id uuid, p_scope text, p_source_epoch text, p_start_at timestamptz, p_end_at timestamptz, p_evidence_refs jsonb, p_request_digest text)
RETURNS TABLE(created boolean, request_digest text, created_at timestamptz) LANGUAGE sql AS $$SELECT true, ''::text, now()$$;

-- sqlc input only: owned by the correlation_network_policy migration.
CREATE TABLE correlation.network_policy_watermarks (
  node_uid uuid NOT NULL,
  source_epoch text NOT NULL,
  acked_through bigint NOT NULL,
  acked_source_time timestamptz,
  last_ack_at timestamptz NOT NULL,
  final_flush_through bigint,
  final_flush_caught_up_at timestamptz,
  PRIMARY KEY (node_uid, source_epoch)
);

CREATE FUNCTION health.record_netpol_collector_gap(p_node_uid uuid, p_boot_id text, p_start_at timestamptz, p_evidence_refs jsonb)
RETURNS uuid LANGUAGE sql AS $$SELECT NULL::uuid$$;
