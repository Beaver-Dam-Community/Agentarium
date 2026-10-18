-- sqlc projection of migrations/20261018092101_evidence_collector_store.up.sql
-- (TASK-08 3.2). It is never installed.
CREATE SCHEMA evidence;
CREATE TABLE evidence.collector_cursors (
  feed text PRIMARY KEY,
  last_received_at timestamptz NOT NULL,
  last_event_id uuid NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE TABLE evidence.destination_observations (
  action_id uuid NOT NULL,
  revision integer NOT NULL,
  attempt_id uuid,
  tenant text NOT NULL,
  evidence_level text NOT NULL,
  rule_id text NOT NULL,
  receipt_digest char(64),
  effect_count integer,
  source_time timestamptz NOT NULL,
  event_id uuid NOT NULL UNIQUE,
  PRIMARY KEY (action_id, revision)
);
CREATE TABLE evidence.receipt_polls (
  action_id uuid PRIMARY KEY,
  first_seen_at timestamptz NOT NULL,
  deadline_at timestamptz NOT NULL,
  next_poll_at timestamptz,
  polls integer NOT NULL DEFAULT 0
);
