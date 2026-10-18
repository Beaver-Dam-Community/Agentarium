-- First release.active_policy row of a new installation (manual, M3-1).
--
-- SPEC-QUESTION (TASK-14, #220 PR body): TASK-14 fixes the activation order
-- (hold -> desired_bundle -> lease ack -> epoch CAS) but not how epoch 1 of a
-- new installation is created, and #220 did not add `first-bundle -activate`.
-- Until that is decided the installer inserts epoch 1 by hand, once, after
-- `tools/first-bundle -publish` wrote release.desired_bundle and the gateway
-- and receiver-sender leases report the same loaded_artifact_digest.
--
--   psql "$INSTALLER_DSN" -v ON_ERROR_STOP=1 \
--     -v environment=prod -v bundle_id=m3-1-first \
--     -v bundle_digest=<first-bundle candidate_digest> \
--     -v artifact_digest=<first-bundle artifact_digest> \
--     -v expected_opa_revision=<first-bundle revision> \
--     -v catalog_digest=<data.json .catalog.catalog_digest of the bundle> \
--     -v change_id=<the -set-by-change-id UUID given to first-bundle> \
--     -v sensor_release_policies_digest=<lock baseline_digests.sensor_release_policies> \
--     -f deploy/gcp/base/installer/m3-1-first-active-policy.sql
--
-- The first bundle has no PolicyChange, so sensor_release_policies_digest is
-- the lock baseline_digests.sensor_release_policies (TASK-14 3.4).
--
-- The row is never replaced: a rerun with the same values is a no-op and a
-- rerun with other values fails the check and rolls back.

\set ON_ERROR_STOP on
BEGIN;

-- The desired bundle must already be this artifact (TASK-14 order).
SELECT 1 / (count(*) = 1)::int AS desired_bundle_matches FROM release.desired_bundle
WHERE environment = :'environment' AND bundle_id = :'bundle_id' AND artifact_digest = :'artifact_digest';

INSERT INTO release.active_policy
  (scope_id, epoch, bundle_id, bundle_digest, artifact_digest, expected_opa_revision, catalog_digest,
   sensor_release_policies_digest, activated_by_change_id, updated_at)
VALUES (:'environment', 1, :'bundle_id', :'bundle_digest', :'artifact_digest', :'expected_opa_revision',
        :'catalog_digest', :'sensor_release_policies_digest', :'change_id'::uuid, now())
ON CONFLICT (scope_id) DO NOTHING;

SELECT 1 / (count(*) = 1)::int AS active_policy_ok FROM release.active_policy
WHERE scope_id = :'environment' AND bundle_id = :'bundle_id' AND bundle_digest = :'bundle_digest'
  AND artifact_digest = :'artifact_digest' AND expected_opa_revision = :'expected_opa_revision'
  AND catalog_digest = :'catalog_digest'
  AND sensor_release_policies_digest = :'sensor_release_policies_digest';

COMMIT;
