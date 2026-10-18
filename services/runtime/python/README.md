# ADK Gateway bridge

This is the TASK-15 model/tool path. `GatewayLlm` uses ADK 2.12.0's custom `BaseLlm` interface. `google-genai` 2.31.0 is used for data types; the runtime never constructs its provider client. `uv.lock` pins the dependencies.

```text
supervisor: assignment → claim → worker observation → readiness → audit ack → go
Python worker: native process_baseline → bootstrap ack → wait for go
ADK: GatewayLlm → IPC → supervisor → Gateway model.generate → sanitized result
ADK functionCall → registered typed tool → same IPC/readiness path → action_result ref
next model turn → explicit model_turn / tool_result refs (no raw parts/signatures)
```

The supervisor owns credentials, the session ID, HTTP, approval waiting and result polling. Its submit IPC completes after those steps; the Python bridge does not receive intermediate HTTP 202 responses. `poll_action` and `request_approval` can only refer to actions already submitted by this bridge. They do not approve an action or resubmit it. A timeout/cancelled IPC channel is closed without retrying an action whose outcome is uncertain.

## Image and installation

`services/runtime/Dockerfile.adk` builds the Go supervisor, a native library from the **same existing isolation package**, and the Python worker. The native library applies TSYNC seccomp to all threads after the final Python exec and before user work. It does not run another executable. The image uses UID 10001 and supports the existing read-only rootfs/drop-ALL configuration.

Set `AGENTARIUM_RUNTIME_MODE=adk` (the ADK image sets it). The supervisor starts `/app/venv/bin/python -I -m agentarium_runtime.worker` with fixed arguments, HOME/TMPDIR only, and the dedicated IPC FD 3. The actual Python executable resolved by the image must be included in the sensor's approved worker binaries; it must not be assumed to be the Go demo executable. The demo image and default `demo` mode remain available. `AGENTARIUM_MAX_CONCURRENT_WORKERS=1` remains required in this implementation.

The `model-config` build context supplies these **non-secret installation artifacts**:

- `model-tools.json`: the same registered four-profile tool map as Gateway/model adapter. The worker uses the ordered `agent` array without rewriting descriptions or schemas. The mandatory `MODEL_TOOLS_DIGEST` build argument is compared using the Go canonical CLI; a mismatch fails the build. The final image records `io.agentarium.model-tools-digest`. Deployment must compare that label and the extracted baked file against the ConfigMap digest.
- `runtime.json`: exactly `model_target_id`, `max_model_calls`, `system_template`. These have no production defaults. The supervisor supplies the IPC timeout at release, derived from its bounded approval/result/readiness budget; there is no independent worker timeout setting. `system_template` is the full server-registered prompt including ADK's fixed suffix `\n\nYou are an agent. Your internal name is "agentarium".`; changing it or the declarations at runtime is rejected.

No credentials are included in these files. Production resource identifiers must come from the permitted environment lock. The worker receives the conversation ID from the supervisor after release; it cannot choose another session. No extra exec Pod ConfigMap volume is required. The deployment renderer, approval UI and production configuration are outside this component PR.

The worker disables the OTel SDK and content capture before ADK imports. The runner also disables per-run message capture/experimental telemetry. No provider retry client is created. NetworkPolicy remains the deployed direct-egress boundary.

## Reproduce the checks

From the repository root:

```sh
go test ./services/runtime/...
uv run --project services/runtime/python pytest services/runtime/python/tests

docker buildx build --load \
  --build-context model-config=services/runtime/python/tests/fixtures/model-config \
  --build-arg MODEL_TOOLS_DIGEST="$(go run ./packages/canonical/cmd/canonical-digest < services/runtime/python/tests/fixtures/model-config/model-tools.json)" \
  -f services/runtime/Dockerfile.adk -t agentarium-runtime-adk:local-test .

docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=128m \
  --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /app/venv/bin/python \
  -v "$PWD/services/runtime/python/tests/linux_worker_check.py:/check.py:ro" \
  agentarium-runtime-adk:local-test /check.py

docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /app/venv/bin/python \
  -v "$PWD/services/runtime/python/tests/linux_isolation_check.py:/check.py:ro" \
  agentarium-runtime-adk:local-test /check.py
```

The fixture config is for the worker-only test, not a deployable shared profile configuration. The container checks execute the actual worker/native filter/ADK loop; a synthetic supervisor supplies model and tool results. They verify stop-before-go, process_baseline, explicit refs and no model output on stdout. The separate native probe confirms execve fails with EPERM.

These checks do **not** establish live Gemini/Gateway integration, GKE sensor observation, production image registration, A/B concurrent workers, Landlock file isolation or TASK-15 completion. The same-UID identity mount limitation of the existing process_baseline remains. Shared spec #270 and model adapter `agent` support are required before deployment.

Approval behavior follows the owner decision in #282 / spec PR #283. The supervisor waits for approval and reevaluates the same action. HOLD_ACTIVE and CONTROL_HEALTH_UNAVAILABLE stop the run; only stale-readiness errors retry with the same request key. An IPC result is usable as a tool reference only when the supervisor confirms a stored final action result. A denied or unresolved action without that record fails the turn explicitly.
