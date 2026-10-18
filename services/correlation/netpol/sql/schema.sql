-- sqlc input only; deployed DDL is the merged audit/health/correlation migrations.
CREATE SCHEMA audit; CREATE SCHEMA health; CREATE SCHEMA correlation;
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
  host_pid integer CHECK (host_pid > 0),   -- required to match the process_exec session worker witness
  container_id text,
  docker_id_prefix text,
  pod_uid uuid,
  netns_inode bigint,
  saddr inet, sport integer, daddr inet, dport integer,   -- socket_tuple. Only when observed
  sock_ptr bigint,                           -- KprobeSock cookie (kernel pointer). Secondary key
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
CREATE TABLE correlation.lifecycle_intervals (
  interval_id uuid PRIMARY KEY,
  cluster_uid uuid NOT NULL,
  pod_uid uuid NOT NULL,
  node_uid uuid NOT NULL,
  boot_id text NOT NULL,
  container_id text NOT NULL,
  restart_instance integer,
  cgroup_inode bigint,
  netns_inode bigint,
  started_at timestamptz,
  ended_at timestamptz,
  end_quality text NOT NULL CHECK (end_quality IN ('observed','inferred_from_other_source','unknown','open')),
  mapping_version integer NOT NULL,
  source_event_ids uuid[] NOT NULL,
  UNIQUE (container_id, mapping_version)
);
CREATE TABLE correlation.correlations (
  correlation_id uuid PRIMARY KEY,
  kernel_event_id uuid NOT NULL,
  revision integer NOT NULL CHECK (revision >= 1),
  action_id uuid,
  attempt_id uuid,
  workload_id text,
  confidence text NOT NULL CHECK (confidence IN ('confirmed','workload_inferred','unlinked')),
  method text NOT NULL,
  evidence_refs jsonb NOT NULL,
  candidate_count integer NOT NULL CHECK (candidate_count >= 0),
  algorithm_version text NOT NULL,
  reason text NOT NULL,
  limitations text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL,
  UNIQUE (kernel_event_id, revision),
  CHECK (confidence <> 'confirmed' OR (attempt_id IS NOT NULL AND candidate_count = 1))
);
CREATE TABLE correlation.network_policy_records (   -- COMMON NetworkPolicyRecord. INSERT only
  record_id uuid PRIMARY KEY,
  cluster_uid uuid NOT NULL,
  node_uid uuid NOT NULL,
  source_epoch text NOT NULL,
  source_sequence bigint NOT NULL CHECK (source_sequence >= 1),
  node_name text NOT NULL,
  source_time timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  disposition text NOT NULL CHECK (disposition IN ('allow','deny')),
  direction text NOT NULL CHECK (direction IN ('ingress','egress')),
  protocol text NOT NULL CHECK (protocol IN ('tcp','udp','icmp')),
  src_ip inet NOT NULL,
  src_port integer,
  dest_ip inet NOT NULL,
  dest_port integer,
  src_endpoint jsonb,
  dest_endpoint jsonb,
  policies jsonb,
  count integer NOT NULL CHECK (count >= 1),
  normalization_version text NOT NULL,
  UNIQUE (node_uid, source_epoch, source_sequence),
  CHECK (disposition = 'allow' OR policies IS NULL),
  CHECK (protocol <> 'icmp' OR (src_port IS NULL AND dest_port IS NULL))
);
CREATE TABLE correlation.network_policy_watermarks (
  node_uid uuid NOT NULL,
  source_epoch text NOT NULL,
  acked_through bigint NOT NULL,
  acked_source_time timestamptz,
  last_ack_at timestamptz NOT NULL,
  final_flush_through bigint,
  final_flush_caught_up_at timestamptz,
  CHECK ((final_flush_through IS NULL) = (final_flush_caught_up_at IS NULL)),
  CHECK (final_flush_through IS NULL OR final_flush_through <= acked_through),
  PRIMARY KEY (node_uid, source_epoch)
);
CREATE TABLE correlation.network_findings (   -- COMMON NetworkFinding. revisions only
  finding_id uuid NOT NULL,
  revision integer NOT NULL CHECK (revision >= 1),
  kind text NOT NULL CHECK (kind IN ('blocked_attempt','unregistered_established',
    'unmatched_attempt','unmatched_deny')),
  outcome text NOT NULL CHECK (outcome IN ('blocked','established','unknown')),
  network_segment text NOT NULL CHECK (network_segment IN ('exec_to_control','exec_to_exec',
    'exec_to_cluster_api','exec_to_metadata','exec_to_internal_other','exec_direct_external',
    'control_to_control','control_to_target','control_to_google_api','control_to_external',
    'unclassified')),
  boundary_crossing text NOT NULL CHECK (boundary_crossing IN ('internal','external','unknown')),
  workload_id text,
  pod_uid uuid,
  node_uid uuid,
  merge_key text NOT NULL,
  kernel_event_ids uuid[] NOT NULL DEFAULT '{}',
  policy_record_ids uuid[] NOT NULL DEFAULT '{}',
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  attempt_count bigint CHECK (attempt_count >= 0),
  count_quality text NOT NULL CHECK (count_quality IN ('exact','estimated','unknown')),
  confidence text NOT NULL CHECK (confidence IN ('workload_inferred','unlinked')),
  rule_version text NOT NULL,
  algorithm_version text NOT NULL,
  reason text NOT NULL,
  limitations text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (finding_id, revision),
  CHECK (window_end >= window_start),
  CHECK ((confidence = 'workload_inferred') = (workload_id IS NOT NULL)),
  CHECK ((kind = 'blocked_attempt') = (outcome = 'blocked')),
  CHECK ((kind = 'unregistered_established') = (outcome = 'established')),
  CHECK (cardinality(kernel_event_ids) + cardinality(policy_record_ids) > 0)
);
CREATE VIEW correlation.network_findings_latest AS
  SELECT DISTINCT ON (finding_id) *
  FROM correlation.network_findings
  ORDER BY finding_id, revision DESC;
CREATE TABLE correlation.network_policy_abandoned_ranges (
  node_uid uuid NOT NULL,
  source_epoch text NOT NULL,
  from_seq bigint NOT NULL,
  to_seq bigint NOT NULL,
  reason text NOT NULL,
  range_digest char(64) NOT NULL,
  gap_id uuid NOT NULL,
  received_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (node_uid, source_epoch, from_seq)
);
CREATE TABLE correlation.network_policy_rotation_losses (
  node_uid uuid NOT NULL,
  source_epoch text NOT NULL,
  after_sequence bigint NOT NULL,
  detected_at timestamptz NOT NULL,
  gap_id uuid NOT NULL,
  received_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (node_uid, source_epoch, after_sequence)
);
CREATE TABLE health.control_health_leases (   -- columns readable by correlation_writer only
  source_id text NOT NULL,
  first_reported_at timestamptz NOT NULL
);
