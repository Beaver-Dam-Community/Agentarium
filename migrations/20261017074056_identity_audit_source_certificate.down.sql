BEGIN;
DROP FUNCTION identity.audit_source_certificate(text,text,text);
-- Schema USAGE may also be needed by other owner-installed limited functions.
-- Do not revoke shared schema access or delete issuance history on rollback.
COMMIT;
