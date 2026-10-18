-- TASK-07 3.2.1: the verification window and the signed manifest created_at
-- come from manifest_intents/export_manifests.created_at. Make both
-- DB-assigned (clock_timestamp at INSERT) and immutable, and remove the
-- exporter's ability to supply them, so a forged old timestamp cannot move a
-- manifest out of the verification window. Never rewrite a merged migration.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('manifest_time_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
CREATE FUNCTION audit._manifest_db_time() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP = 'INSERT' THEN
  NEW.created_at := clock_timestamp();
  RETURN NEW;
 END IF;
 IF NEW.created_at IS DISTINCT FROM OLD.created_at THEN
  RAISE EXCEPTION 'manifest created_at is DB-assigned and immutable' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION audit._manifest_db_time() FROM PUBLIC;
CREATE TRIGGER manifest_intents_db_time BEFORE INSERT OR UPDATE ON audit.manifest_intents
 FOR EACH ROW EXECUTE FUNCTION audit._manifest_db_time();
CREATE TRIGGER export_manifests_db_time BEFORE INSERT OR UPDATE ON audit.export_manifests
 FOR EACH ROW EXECUTE FUNCTION audit._manifest_db_time();
-- Column grants: the exporter can no longer name created_at at all.
REVOKE INSERT, UPDATE ON audit.manifest_intents, audit.export_manifests FROM audit_exporter;
GRANT INSERT (chain_id, manifest_seq, batch_id, fencing_token) ON audit.manifest_intents TO audit_exporter;
GRANT INSERT (chain_id, manifest_seq, object_generation, batch_digest, prev_manifest_digest, manifest_digest,
  kms_key_version, signature, manifest_object_key, fencing_token) ON audit.export_manifests TO audit_exporter;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('manifest_time_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
