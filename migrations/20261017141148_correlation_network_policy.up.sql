-- TASK-10 3.7: NetworkPolicyRecord storage, per-node ack watermarks, derived
-- NetworkFinding revisions and the netpol collection-gap grants.
-- Requires the merged audit, health and correlation lifecycle installations.
-- The installer owns DDL. Runtime cannot UPDATE/DELETE records or findings.
-- timeline_reader stays pending as in the earlier correlation migrations.
BEGIN;
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
CREATE INDEX network_policy_records_match
  ON correlation.network_policy_records (dest_ip, dest_port, protocol, source_time);
CREATE INDEX network_policy_records_time ON correlation.network_policy_records (source_time);

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
CREATE INDEX network_findings_workload ON correlation.network_findings (workload_id, window_start)
  WHERE workload_id IS NOT NULL;
CREATE INDEX network_findings_merge ON correlation.network_findings (merge_key, window_end);

CREATE VIEW correlation.network_findings_latest AS
  SELECT DISTINCT ON (finding_id) *
  FROM correlation.network_findings
  ORDER BY finding_id, revision DESC;

REVOKE ALL ON correlation.network_policy_records, correlation.network_policy_watermarks,
  correlation.network_findings, correlation.network_findings_latest FROM PUBLIC;
GRANT SELECT, INSERT ON correlation.network_policy_records, correlation.network_findings TO correlation_writer;
GRANT SELECT, INSERT, UPDATE ON correlation.network_policy_watermarks TO correlation_writer;
GRANT SELECT ON correlation.network_findings_latest TO correlation_writer;
-- Health controller decides NETPOL_COLLECTOR_STOPPED start_at from acked source times.
GRANT SELECT ON correlation.network_policy_watermarks TO control_health_writer;
COMMIT;
