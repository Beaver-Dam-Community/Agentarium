-- TASK-14 desired_bundle (COMMON policy deployment contract, TASK-14 3.2). M2-6a.
-- One row per environment, written only by the releaser (here the bootstrap
-- tool tools/first-bundle). gateway and adapter poll it every 2 s.
--
-- Not in this migration:
--   * active_policy and its epoch: created with the activation flow
--     (M2-6 / the rest of TASK-14), so the first bundle is not activated by
--     skipping the hold → lease ack → epoch CAS order.
--   * GRANTs: the writer role (releaser_app) and the readers (gateway,
--     adapter, control_health_writer) do not exist yet. Who creates them is
--     an open cross-task question; see the M2-6a PR and its issue.
--
-- SPEC-QUESTION: the schema name is not specified. TASK-14 tables go in the
-- "release" schema here, as other Tasks use their own schema.

CREATE SCHEMA release;

CREATE TABLE release.desired_bundle (
  environment      text PRIMARY KEY CHECK (environment <> ''),
  bundle_id        text NOT NULL CHECK (bundle_id <> ''),
  artifact_digest  text NOT NULL CHECK (artifact_digest ~ '^[0-9a-f]{64}$'),
  object_uri       text NOT NULL,
  -- SPEC-QUESTION: the first bundle has no PolicyChange; the bootstrap value
  -- of set_by_change_id is an open question (see the M2-6a issue, #30).
  set_by_change_id uuid NOT NULL,
  set_at           timestamptz NOT NULL,
  -- object_uri = gs://<bucket>/bundles/<artifact_digest>.tar.gz
  CONSTRAINT desired_bundle_object_uri CHECK (
    object_uri ~ '^gs://[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]/bundles/[0-9a-f]{64}\.tar\.gz$'
    AND right(object_uri, 71) = artifact_digest || '.tar.gz'
  )
);
