-- Refuses to destroy recorded network evidence; history needs a forward migration.
BEGIN;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM correlation.network_policy_records) OR EXISTS (SELECT 1 FROM correlation.network_findings) THEN
    RAISE EXCEPTION 'network policy records or findings exist; refusing to drop evidence' USING ERRCODE='55000';
  END IF;
END $$;
DROP VIEW correlation.network_findings_latest;
DROP TABLE correlation.network_findings;
DROP TABLE correlation.network_policy_watermarks;
DROP TABLE correlation.network_policy_records;
COMMIT;
