-- name: ResolveBinding :one
SELECT b.secret_resource,b.secret_version,b.header_name,b.header_format
FROM broker.credential_bindings b
JOIN coordinator.attempt_credential_scope a ON a.attempt_id=sqlc.arg(attempt_id)::uuid
 AND a.adapter_id=b.adapter_id AND a.operation_id=b.operation_id AND a.state='planned'
 AND a.adapter_namespace=sqlc.arg(namespace)::text AND a.adapter_ksa=sqlc.arg(ksa)::text
WHERE b.credential_binding=sqlc.arg(binding)::text AND b.adapter_id=sqlc.arg(adapter_id)::text AND b.enabled;

-- name: CheckPermissions :one
SELECT (pg_has_role(current_user,'broker_reader','MEMBER')
 AND has_schema_privilege(current_user,'broker','USAGE')
 AND has_schema_privilege(current_user,'coordinator','USAGE')
 AND has_table_privilege(current_user,'broker.credential_bindings','SELECT')
 AND has_column_privilege(current_user,'coordinator.attempt_credential_scope','attempt_id','SELECT')
 AND has_column_privilege(current_user,'coordinator.attempt_credential_scope','adapter_id','SELECT')
 AND has_column_privilege(current_user,'coordinator.attempt_credential_scope','operation_id','SELECT')
 AND has_column_privilege(current_user,'coordinator.attempt_credential_scope','state','SELECT')
 AND has_column_privilege(current_user,'coordinator.attempt_credential_scope','adapter_namespace','SELECT')
 AND has_column_privilege(current_user,'coordinator.attempt_credential_scope','adapter_ksa','SELECT'))::boolean AS allowed;
