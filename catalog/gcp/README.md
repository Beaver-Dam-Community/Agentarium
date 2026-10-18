# catalog/gcp

GCP/GKE agent-control catalog for the two MVP workloads. Contract owner: `docs/tech-specs/TASK-02-catalog-contracts.md`
(3 items 1-3, 3.2, 3.3, 6, 9, Appendix A); shared enums come from `docs/tech-specs/COMMON.md`.

| File | What it is |
| --- | --- |
| `operations.yaml` | Registered operations (`k8s.*`, `receiver.submit`, `model.generate`, `evidence.*`, `discovery.*`): adapter, route, limits, disclosure, evidence strategy, redaction, content checks. |
| `targets.yaml` | Registered targets: origin, TLS name, CA, allowed CIDRs, max data class, namespace/model. Installer-supplied values are `<...>` placeholders resolved from `deploy/gcp/environment.lock.json` (TASK-16); no real project IDs or addresses are committed. |
| `schema/operations.schema.json`, `schema/targets.schema.json` | JSON Schema (draft 2020-12), copied from TASK-02 Appendix A. Source of truth for fields, types and enums. |

`catalog_digest` = SHA-256(JCS({operations sorted by operation_id, targets sorted by target_id})) after strict YAML decode
(unknown fields and duplicate keys rejected). Any change here, including an address or CIDR, changes the digest and requires
re-evaluation and tests. `catalog_version` is a display label only. Entries marked `# SPEC-QUESTION:` are narrow readings of
ambiguous spec text and need an owner decision.

## Validate

Parse with duplicate-key rejection, then validate each file against its schema (for example with `uv run --with pyyaml
--with jsonschema`). The `<location>` placeholder in the `agent-platform-gemini` origin does not match the schema's origin
pattern until rendered from the lock; every other field validates as committed.
