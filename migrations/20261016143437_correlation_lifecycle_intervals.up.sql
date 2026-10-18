-- TASK-10 3.3: only the documented derived interval relation.
-- The installer owns DDL; correlation_writer is never the table/schema owner.
-- control_health_writer must be installed by TASK-10 health bootstrap first.
-- timeline_reader is intentionally pending: COMMON requires tenant-filtered
-- views while TASK-10's DDL grants the base table. No broad cross-tenant grant.
BEGIN;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='correlation_reader') THEN
    CREATE ROLE correlation_reader NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='correlation_writer') THEN
    CREATE ROLE correlation_writer NOLOGIN;
  END IF;
END $$;
GRANT correlation_reader TO correlation_writer;
CREATE SCHEMA IF NOT EXISTS correlation;
REVOKE ALL ON SCHEMA correlation FROM PUBLIC;
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
CREATE INDEX lifecycle_intervals_container ON correlation.lifecycle_intervals (container_id, started_at);
CREATE INDEX lifecycle_intervals_cgroup ON correlation.lifecycle_intervals (node_uid, boot_id, cgroup_inode);
REVOKE ALL ON correlation.lifecycle_intervals FROM PUBLIC;
GRANT USAGE ON SCHEMA correlation TO correlation_writer, control_health_writer;
GRANT SELECT, INSERT ON correlation.lifecycle_intervals TO correlation_writer;
GRANT SELECT ON correlation.lifecycle_intervals TO control_health_writer;
-- Cross-schema source SELECT belongs to the audit/coordinator owner migrations.
COMMIT;
