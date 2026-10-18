-- TASK-03 restricted lookup for TASK-07. Depends on shared spec PR #93.
-- This is metadata authorization, not TLS chain verification. The receiver
-- must obtain the serial and exact SAN from its verified TLS peer.
BEGIN;
CREATE FUNCTION identity.audit_source_certificate(
    certificate_serial text, exact_san text, requested_boot_hash text DEFAULT NULL
) RETURNS TABLE (
    namespace text, ksa text, node_uid uuid,
    certificate_boot_id text, historical_boot_id text
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, identity, pg_temp
AS $function$
    SELECT c.namespace, c.ksa, c.node_uid, c.boot_id,
        (
            SELECT prior.boot_id
            FROM identity.issued_certificates AS prior
            WHERE requested_boot_hash IS NOT NULL
              AND prior.san_uri = c.san_uri
              AND prior.namespace = c.namespace AND prior.ksa = c.ksa
              AND prior.node_uid = c.node_uid
              AND prior.boot_id IS NOT NULL AND prior.boot_id <> ''
              AND prior.issued_at <= c.issued_at
              AND prior.expires_at > prior.issued_at
              AND encode(sha256(convert_to(prior.boot_id, 'UTF8')), 'hex') = requested_boot_hash
            -- Expiry/revocation forbids current authentication, but does not
            -- erase previously issued same-node boot provenance.
            ORDER BY prior.issued_at DESC, prior.serial
            LIMIT 1
        )
    FROM identity.issued_certificates AS c
    JOIN identity.registered_workloads AS w
      ON w.namespace = c.namespace AND w.ksa = c.ksa
    WHERE c.serial = certificate_serial AND c.san_uri = exact_san
      -- Issuer and TLS handlers use hex.EncodeToString(serial.Bytes()).
      AND certificate_serial ~ '^([0-9a-f]{2})+$'
      AND octet_length(certificate_serial) <= 16384
      AND octet_length(exact_san) <= 16384
      AND (requested_boot_hash IS NULL OR requested_boot_hash ~ '^[0-9a-f]{64}$')
      AND c.issued_at <= statement_timestamp()
      AND statement_timestamp() < c.expires_at
      AND c.revoked_at IS NULL
      AND w.enabled AND w.role = 'service' AND w.service_principal = w.ksa
      AND exact_san = 'spiffe://agentarium.internal/ns/' || w.namespace || '/sa/' || w.ksa;
$function$;

-- Keep the existing identity object owner; do not make the runtime service or
-- audit_writer a table/function owner or give them base-table SELECT.
DO $owner$
DECLARE identity_owner name;
BEGIN
    SELECT pg_get_userbyid(c.relowner) INTO identity_owner
      FROM pg_class c WHERE c.oid = 'identity.issued_certificates'::regclass;
    IF identity_owner IS DISTINCT FROM (
        SELECT pg_get_userbyid(c.relowner) FROM pg_class c
         WHERE c.oid = 'identity.registered_workloads'::regclass
    ) THEN
        RAISE EXCEPTION 'identity certificate and registry owners must match';
    END IF;
    EXECUTE format('ALTER FUNCTION identity.audit_source_certificate(text,text,text) OWNER TO %I', identity_owner);
END
$owner$;
REVOKE ALL ON FUNCTION identity.audit_source_certificate(text,text,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA identity TO audit_writer, audit_owner;
GRANT EXECUTE ON FUNCTION identity.audit_source_certificate(text,text,text) TO audit_writer, audit_owner;
COMMENT ON FUNCTION identity.audit_source_certificate(text,text,text) IS
    'Restricted live service certificate metadata and retained same-node boot provenance; retain issuance metadata for the WAL/raw retention period.';
COMMIT;
