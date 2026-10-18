# Documentation source scope

These rules apply when writing or revising files in `docs/` and the repository README.

- Use the plan, architecture, and common technical contract in `docs/` as design sources. Their proposed APIs and controls are not implementation evidence.
- For implementation evidence, inspect only project GCP code and run artifacts under `platform/gcp/`, `deploy/gcp/`, `catalog/gcp/`, `policies/`, `packages/`, `services/`, `runtime/`, `apps/`, `migrations/`, `workers/`, `sensors/`, `tests/`, `tools/`, and `evidence/gcp/`. Confirm exact files and execution results before citing them.
- Do not read, cite, link, or infer GCP functionality from other repository trees. Expand the source scope only when the user changes the documentation scope.
- Keep planned behavior, code existence, and verified runtime results distinct. Use official product documentation for vendor behavior and record versions or support limits that matter to the design.
