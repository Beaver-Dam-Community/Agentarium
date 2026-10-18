-- Explicit development rollback destroys derived history. Production recovery
-- uses a forward migration. Keep shared schema/group roles for other sections.
BEGIN;
DROP TABLE correlation.lifecycle_intervals;
COMMIT;
