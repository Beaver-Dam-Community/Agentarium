-- sqlc input; deployed DDL is the correlation_lifecycle_intervals migration.
CREATE SCHEMA correlation;
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
