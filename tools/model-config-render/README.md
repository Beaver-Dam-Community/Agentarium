# Model installation artifacts

Render COMMON Appendix B's approved model installation input without modifying the cluster or choosing production model settings:

```sh
go run ./tools/model-config-render \
  --lock deploy/gcp/environment.lock.json \
  --catalog catalog/gcp \
  --out /tmp/agentarium-model-config
```

The lock must contain `project.id` and `model` with exactly `model_id`, `model_region`, `api_version`, `profiles`, and `tools`. The renderer uses `canonical.ParseModelProfiles`, enforces TASK-05 request limits and the intent-check token limit, checks all four registered tool arrays (names/order, exact declaration fields, description/parameter size, canonical JSON grammar), and compares every model target and generateContent route against the lock. It does not change the catalog or supply missing values. Duplicate keys, missing model config, inconsistent limits and catalog mismatch fail before output is created.

Outputs:

- `model-profiles.json`, `model-tools.json`: JCS bytes from that one lock.
- `configmaps.json`: immutable ConfigMaps with identical data and digest annotations in agent-control, agent-adapters, and agent-observe. Their content-derived name is in `digests.json`.
- `digests.json`: canonical file digests plus the checked catalog digest, for installation evidence.

Consumer Deployments must mount that generated ConfigMap read-only and use their component's existing profile/tool file flags. This command does not patch Deployments. Runtime image builds use the same `model-tools.json` and compare the build argument to its Go canonical digest (runtime PR #281). Before deploying an approved image, extract its baked file and run the renderer with `--verify-runtime-tools <extracted-model-tools.json>`; whitespace is immaterial, but changed descriptions, parameter types or array order fail. This file comparison does not attest the image signature or admission approval.

The command refuses to overwrite an existing output directory. Generated artifacts contain only the two model sections, never the whole lock or credentials. Keep real resource identifiers in the permitted environment lock; do not commit generated environment artifacts here.

`go test -race ./tools/model-config-render` verifies namespace equality/digests, stale image rejection, catalog/config mismatches, limits, duplicate JSON keys and non-overwrite behavior. These are offline installation checks. Provider-specific schema/`thinkingConfig` support and tools-plus-schema/history Q0 must still be run with the selected Gemini model; successful rendering is not Q0, deployment, or end-to-end verification. The command does not validate provider-specific JSON Schema semantics or prove that a production output schema equals its service's versioned schema. Production values remain operator-reviewed installation inputs; there are no model/config defaults.
