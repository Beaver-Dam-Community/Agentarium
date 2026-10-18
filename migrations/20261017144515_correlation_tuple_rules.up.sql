-- TASK-10 3.1/3.6: Q0-measured tuple normalization rules. Rows come only from
-- recorded Q0 runs; without a rule no destination is promoted to confirmed.
-- The installer owns DDL and inserts measured rows; runtime reads them.
BEGIN;
CREATE TABLE correlation.tuple_normalization_rules (
  algorithm_version text NOT NULL,
  service_vip inet NOT NULL,
  service_port integer NOT NULL CHECK (service_port BETWEEN 1 AND 65535),
  endpoint_cidr cidr NOT NULL,
  endpoint_port integer NOT NULL CHECK (endpoint_port BETWEEN 1 AND 65535),
  kernel_side text NOT NULL CHECK (kernel_side IN ('vip','endpoint')),
  adapter_side text NOT NULL CHECK (adapter_side IN ('vip','endpoint')),
  measured_run_id text NOT NULL CHECK (measured_run_id <> ''),
  PRIMARY KEY (algorithm_version, service_vip, service_port, endpoint_cidr)
);
REVOKE ALL ON correlation.tuple_normalization_rules FROM PUBLIC;
GRANT SELECT ON correlation.tuple_normalization_rules TO correlation_writer;
COMMIT;
