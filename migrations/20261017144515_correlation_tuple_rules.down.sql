-- Measured Q0 rules are evidence for stored correlations; refuse to drop them.
BEGIN;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM correlation.tuple_normalization_rules) THEN
    RAISE EXCEPTION 'measured normalization rules exist; refusing to drop' USING ERRCODE='55000';
  END IF;
END $$;
DROP TABLE correlation.tuple_normalization_rules;
COMMIT;
