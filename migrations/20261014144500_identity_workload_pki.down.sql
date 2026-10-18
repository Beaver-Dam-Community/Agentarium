-- Reverts 20261014144500_identity_workload_pki.up.sql. identity_app is left in
-- place because later identity migrations and Cloud SQL IAM users depend on it.

DROP VIEW IF EXISTS identity.work_readiness_session_view;
DROP TABLE IF EXISTS identity.session_budgets;
DROP TABLE IF EXISTS identity.sessions;
DROP TABLE IF EXISTS identity.issued_certificates;
DROP TABLE IF EXISTS identity.registered_workloads;
DROP SCHEMA IF EXISTS identity;
