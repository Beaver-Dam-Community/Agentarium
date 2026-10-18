-- sqlc input only; deployed DDL is the merged migrations.
CREATE SCHEMA audit; CREATE SCHEMA correlation; CREATE SCHEMA coordinator;
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
  sock_ptr text,                           -- KprobeSock cookie (kernel pointer). Secondary key
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
CREATE TABLE correlation.tuple_normalization_rules (
  algorithm_version text NOT NULL,
  service_vip inet NOT NULL,
  service_port integer NOT NULL CHECK (service_port BETWEEN 1 AND 65535),
  endpoint_cidr cidr NOT NULL,
  endpoint_port integer NOT NULL CHECK (endpoint_port BETWEEN 1 AND 65535),
  kernel_side text NOT NULL CHECK (kernel_side IN ('vip','endpoint')),
  adapter_side text NOT NULL CHECK (adapter_side IN ('vip','endpoint')),
  measured_run_id text NOT NULL CHECK (measured_run_id <> ''),
  PRIMARY KEY (algorithm_version, service_vip, service_port, endpoint_cidr)
);
CREATE TABLE coordinator.attempts (attempt_id uuid PRIMARY KEY, action_id uuid NOT NULL, adapter_node_uid uuid NOT NULL);
CREATE TABLE coordinator.attempt_observations (
    attempt_id          uuid PRIMARY KEY,
    local_addr          inet NULL,
    local_port          integer NULL,
    peer_addr           inet NULL,
    peer_port           integer NULL,
    netns_inode         bigint NULL,
    pod_uid             uuid NULL,
    connect_started_at  timestamptz NULL,
    send_started_at     timestamptz NULL,
    send_finished_at    timestamptz NULL,
    response_at         timestamptz NULL,
    provider_request_id text NULL,
    k8s_audit_id        text NULL,
    wire_body_digest    char(64) NULL,
    recorded_at         timestamptz NOT NULL
);
