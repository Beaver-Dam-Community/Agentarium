CREATE SCHEMA correlation;
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
CREATE INDEX correlations_attempt ON correlation.correlations (attempt_id) WHERE attempt_id IS NOT NULL;
