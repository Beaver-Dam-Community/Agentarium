<a id="shared-tech-spec-ref"></a>

# Shared Tech Spec

> Implementation specification as of 2026-10-11. Baseline: the working tree after efe8dce (2026-10-11 revision). This is the source of truth (SSOT) shared by the [final plan](../plan.md) and the 16 Tech Specs. Structures, fields, enums, reason codes, event_type values, and API names follow this document, and Task documents refer to this document or use the same names. The schema blocks in plan.md are conceptual summaries. The APIs, storage structures, check rules, and default values below are a contract that implementers must follow; implementation, deployment, and measurement are all planned and have not been carried out yet.

## Implementation stack and decision status

| Area | Implementation decision | Values to pin and verify at installation |
| --- | --- | --- |
| Implementation languages | Go (control, sending, storage, node components), Python 3.12 (ADK runtime, AI assist services, timeline, regression evaluation), TypeScript/React (console). The [Languages and paths by service](#languages-and-paths-by-service) table below is the source of truth for paths | Go and Python patch versions, image digests, `go.sum` and Python lock |
| HTTP server | Go standard `net/http` (the `chi` router if needed). Python services use FastAPI + Pydantic v2 | Router and middleware versions |
| Strict JSON | Go: a pre-check based on `json.Decoder.Token()` checks duplicate keys, depth, and number ranges, then decodes with `DisallowUnknownFields` + `UseNumber`. Python: Pydantic strict + extra rejection | Depth and size limits, test vectors |
| Normalization, JCS, hash | Only the shared Go package `packages/canonical/` computes these. The gateway and adapters use the same package. Python components do not compute `action_digest` | JCS candidate `github.com/cyberphone/json-canonicalization` (Go implementation of RFC 8785). The owner confirms the repository, license, and version, and it is finalized after passing the RFC vectors |
| Atomic state | Cloud SQL for PostgreSQL, row locks, unique constraints, `statement_timestamp()` | Supported DB version, private connection/authentication, backup/restore, cost |
| DB access | Go: `pgx` v5 + `sqlc`. Python: psycopg 3 (mostly reads; writes go through the owning service's API). Migrations are unified on a single tool, `golang-migrate` (SQL files, `migrations/`) | Dependency lock, READ COMMITTED, migration digest |
| Policy | OPA is embedded in the gateway process as the Go library `github.com/open-policy-agent/opa/v1/rego` (no sidecar). The gateway and adapters read the `desired_bundle` row written by the releaser every 2 seconds, fetch the signed bundle (OPA bundle signing) object that the row points to from GCS, verify the signature with the `v1/bundle` reader, and load it. The gateway directly records the bundle `Manifest.Revision` used for evaluation. `v1/sdk` is not used ([policy decision contract](#policy-decision-contract)) | OPA module version (identical in the gateway and `tools/decision-replay/`), signing key and `keyID`, active revision |
| External calls (adapter) | Go `net/http.Transport{DialContext, DisableKeepAlives: true, ForceAttemptHTTP2: false, DisableCompression: true}`, `tls.Config{ServerName, VerifyConnection}`, `httptrace.ClientTrace` (`ConnectStart/ConnectDone`, `GotConn`, `WroteHeaders`, `WroteRequest`, `GotFirstResponseByte`); `CheckRedirect` always returns `http.ErrUseLastResponse`. A new connection per attempt (connection reuse is not supported). The `failed`/`unknown` boundary is `WroteHeaders` | DNS/connection IP and TLS/SNI checks, trace hook tests |
| Model calls | The Go model adapter calls the Gemini REST `generateContent` of Gemini Enterprise Agent Platform (formerly Vertex AI, hereafter Agent Platform) directly. Every AI call goes through the model adapter and the `model.generate` operation (REST + a `golang.org/x/oauth2/google` WIF token, to avoid hidden calls in the Go SDK). Preserving thought signatures is the adapter's responsibility | Model/region, API version, `thinkingConfig`, temperature, output schema support |
| Deployment | GKE Standard, Dataplane V2 (`ADVANCED_DATAPATH`), `platform/gcp/` Terraform, `deploy/gcp/` Kustomize | Project/region, node image/kernel, containerd version |
| Regression test environment | A separate cluster in a separate GCP project. Reuses the TASK-01 Terraform module with `env = regression` | Confirm project ID and WIF pool separation |
| Identity and secrets | User OIDC (Google), service mTLS (Certificate Authority Service DevOps tier CA pool, issued only by the identity service, [service PKI](#service-pki-and-identifiers)), per-role KSA/WIF for GKE, Secret Manager, credential broker in `agent-control` | IdP client, certificate rotation, minimal resource binding |
| Observability | Tetragon (JSON file export + inode/offset checkpoint), Go exporter and lifecycle recorder, OTel Collector, GCS evidence objects (KMS-signed manifest chain) | Hooks, permissions, rotation limits, filters, loss metrics |
| UI | `apps/console/` React/TypeScript UI for approval, timeline, and policy changes. Authorization and storage are the server's responsibility | Dependency lock, browser support |
| Agent runtime | A trusted supervisor in one Pod/single container + a dedicated fresh-exec worker per session. Google ADK (Python, `runtime/adk/`). Tools wrap only `submit_action`, `poll_action`, and `request_approval(action_id)` | ADK and google-genai versions, recheck the custom model extension point |

### Languages and paths by service

This table is the source of truth for paths. If a path in a Task document differs, this table prevails.

| Language | Component and path | Owning Task |
| --- | --- | --- |
| Go | gateway `services/gateway/` (embedded OPA) | TASK-04 |
| Go | bundle loading `packages/policyloader/` (digest and signature verification of the object pointed to by `desired_bundle`, and prepared query creation; shared by the gateway, adapters, and `tools/decision-replay/`) | TASK-04 |
| Go | dispatch coordinator `services/coordinator/` | TASK-03 |
| Go | identity and certificate service `services/identity/` (sessions, approvals, service sessions, workload certificates; there is no separate `services/approval/`) | TASK-03 |
| Go | display contract renderer `packages/contractview/` (shared by the approval screen and intent check input; also imported by the TASK-04 gateway) | TASK-03 |
| Go | four adapters `services/adapters/{kubernetes-reader,receiver-sender,model,evidence-reader}/` | TASK-05 |
| Go | credential broker `services/credential-broker/` | TASK-06 |
| Go | audit writer and outbox exporter `services/audit/` | TASK-07 |
| Go | test receiver `services/receiver/`, evidence collector `services/evidence-collector/` | TASK-08 |
| Go | runtime guard (NRI plugin, containerd `nri/pkg/stub`) `sensors/runtime-guard/`, exporter `sensors/exporter/`, lifecycle recorder `services/lifecycle-recorder/` | TASK-09 |
| Go | node readiness controller `services/node-readiness/` (removes the startup taint) | TASK-01 |
| Go | health controller `services/control-health/` (includes the probe runner and baseline drift probe), correlation `services/correlation/` (client-go informer) | TASK-10 |
| Go | start coordinator `services/start-coordinator/` (dedicated to `startup_guard_gate`) | TASK-10 |
| Go | releaser `services/releaser/` | TASK-14 |
| Go | bundle builder `packages/bundles/` (candidate bundle creation, `candidate_digest`, OPA bundle signing) | TASK-14 |
| Go | normalization, JCS, hash `packages/canonical/` (owns the test vectors `vectors.json`). Digest CLI for Python tools `packages/canonical/cmd/canonical-digest/` | TASK-02 |
| Go | policy diff and permission widening check `packages/policydiff/` | TASK-14 |
| Go | decision replay `tools/decision-replay/` (same OPA version as the gateway) | TASK-13 |
| Go | regression request relay `services/regression-dispatcher/` (production project `agent-release`; relays the bucket in the [regression test contract](#regression-test-contract)) | TASK-13 |
| Python | ADK runtime `runtime/adk/` (includes the supervisor, dedicated worker bootstrap, Linux isolation settings, and application session bridge) | TASK-15 |
| Python | policy proposal `services/proposer/` | TASK-12 |
| Python | intent check `services/intent_check/` (model calls go through the gateway) | TASK-04 |
| Python | discovery analyzer `services/discovery/` | TASK-02 |
| Python | timeline, alignment, and evidence API `services/timeline/`, `packages/alignment/` | TASK-11 |
| Python | regression harness and evaluation `tools/regression/`, `packages/evaluation/` | TASK-13 |
| Python | integration runner `tools/integration_runner/` | TASK-15 (TASK-16 only references it) |
| TypeScript/React | `apps/console/` (the policy change screen `apps/console/policy-changes` belongs to TASK-14) | TASK-03/11/14 |

Python components only submit ClientActions; the Go gateway performs normalization and hashing. When Python needs a digest, it uses the result of the gateway API. Go also computes the digest for the two remaining paths where the Python side needs one.

- candidate bundle: The TASK-12 proposal service does not call `packages/bundles/` directly. TASK-14 `POST /internal/policy-diff:check` builds the candidate bundle with `packages/bundles/` and returns `candidate_digest` together with `permission_widening`.
- regression test report: `tools/regression/` (Python) passes the report JSON to the Go CLI `packages/canonical/cmd/canonical-digest/` and receives `report_digest`. Python code does not reimplement JCS or hashing.

Subpaths not in the table (for example TASK-05 `packages/transport/`, TASK-04 `packages/decisions/`, TASK-09 `sensors/tetragon/policies/`, TASK-16 `tools/docs-check/`) are internal paths used only within the owning Task, and the implementation file table of each Task document defines them.

### Decision status

| Status | Items |
| --- | --- |
| Decided | GKE Standard, Dataplane V2, Google ADK (Python), a separate project for the regression test environment, role split among Go/Python/TypeScript, OPA embedded in the gateway (no sidecar), dispatch coordinator placed in TASK-03 `services/coordinator/`, decision authentication is "mTLS service connection + immutable DB decision row" (not a signature scheme), four adapter Deployments (kubernetes-reader, receiver-sender, model, evidence-reader), the Agent Platform call path is the `private.googleapis.com` VIP of Private Google Access, migration tool `golang-migrate`, `startup_guard_gate` split out as an independent gate |
| Decided but version not fixed | Go JCS library (the candidate has no releases, so it will be vendored by commit SHA and finalized after passing the vectors), patch versions of OPA, Tetragon, ADK, pgx, and sqlc |
| Q0 verification items | The [shared Q0 list](#common-q0-list) below |

### Common Q0 list

| Area | Items |
| --- | --- |
| Node and runtime | NRI/runtime handler path and its persistence across upgrades, keeping NRI configuration on the COS rootfs (read-only), access to containerd and the NRI socket on GKE nodes, conflicts between automatic DaemonSet tolerations and VAP, method for comparing image digests |
| Kernel observation | How Tetragon reports state-transition events in softirq context, the load of the state-transition filter (local connect map, TTL 120 seconds), Dataplane V2 tuple normalization (bidirectional DNAT measurement depending on whether socket LB is used), Dataplane V2 metadata server address and port |
| Identity and network | Whether traffic originating from hostNetwork Pods and nodes on Dataplane V2 matches a NetworkPolicy `ipBlock` (node CIDR) (if not, the alternative is to change the sensor collection path to a node-local relay), whether `169.254.169.252:988` is needed on the WIF metadata path, whether TokenReview provides the `pod-uid` extra (on the pinned GKE version), whether the Auth Proxy receives an IAM token under NetworkPolicy, whether any API uses the PGA 34.126.0.0/18 path, CAS DevOps tier limits, the PGA path for Google OIDC token and JWKS hosts |
| Model | Location of the Gemini 3 model (whether it is `global` only) and the PGA path and `model_region`, using `responseSchema` together with function calling, the `thinkingConfig` format, model timeout and token limits, persistence of the `BaseLlm` interface in the pinned ADK version |
| Policy and audit | OPA ES256 verification and KMS signature format, k8s `Audit-Id` linkage |
| Network policy logs | Whether the fields and behavior of `policy-action` records on the pinned GKE version match the official documentation, the format and rotation limits of the node file (`/var/log/network/policy_action.log*`), the mounts and permissions the node collector needs to read the file, the delivery delay until records are stored, the loss metric (the names and collection method of the `policy_logging`-related counters in node anetd metrics), the destination address recorded after Service address translation (ClusterIP or backend address), whether traffic originating from hostNetwork Pods and nodes is recorded, the loss pattern at the limit of 500 records per second per node, which point in the 5-second interval the `timestamp` of an aggregated record refers to, whether a `_Default` sink exclusion actually prevents `policy-action` logs from being stored (that items not stored are not charged was confirmed in the [pricing documentation](https://cloud.google.com/stackdriver/pricing)) |

### environment lock

The source-of-truth file for installation values is `deploy/gcp/environment.lock.json`, and its schema is owned by TASK-16. The keys referenced by COMMON and their default values are as follows.

| key | Default value and content |
| --- | --- |
| Node | Image `COS_CONTAINERD` (version pinned), private nodes, release channel `REGULAR` + node pool maintenance exclusion, IPv4 only, machine type `e2-standard-4` (can be changed in the lock) |
| Runtime paths | containerd socket `/run/containerd/containerd.sock`, NRI socket path (pinned after confirmation in Q0) |
| Versions | Versions of Go, Python, the OPA module, pgx, sqlc, golang-migrate, Tetragon, ADK, google-genai |
| Model | Common model ID, location, API version + per-profile generation settings, schema, limits, registered tools ([Appendix B](#appendix-b-modelgenerate-integration-contract)). Timeouts follow the fixed table in TASK-05 |
| Storage | Bucket names for evidence, summaries, bundles, `decision-input-exports`, `regression-requests`, `regression-reports`, and the Cloud SQL instance |
| Policy deployment | Bundle bucket, `desired_bundle` polling interval (2 seconds), keyID (`prod-v1`, regression `regression-v1`), ack timeout (120 seconds) |
| Time limits | decision/permit TTL, intent check wait (3 seconds), sweeper/outcome (60 seconds), work_readiness.challenge_timeout_seconds (15 seconds) and maximum_result_age_seconds (3 seconds, also applied to node results) |
| Session worker | session_workers.mode=dedicated_process, uid=10001, pinned worker_command_digest and process_baseline profile digest, max_concurrent_workers and termination_deadline_seconds required after measurement. The verification of the default worker gate/file hardening and the Landlock ABI are recorded separately |

Patch versions and image digests are pinned in implementation CI by the dependency lock and the environment lock. When the stack or a security boundary changes, the related specification and regression tests are changed together. "Confirmed" in the table above means that the design decision has been confirmed, not that installation or functional verification has been completed.

## Terminology rules

Technical terms are kept in the original language and explained where they first appear. Code, API, and field names are not translated.

| Term | Meaning in this project |
| --- | --- |
| Atomic state / Atomicity | Approval counts, reservations, attempts, and the audit outbox are committed or rolled back together in a single DB transaction. Atomicity of remote effects is not included. |
| Admission | The API server checks Pod creation and modification specs against policy before storing them. |
| RBAC | Restricts which Kubernetes resources a service account can use and with which actions. |
| transaction | Groups DB changes that must succeed or be canceled together into a single processing unit. |
| outbox | A durable pending-delivery record stored in the same transaction as the business state. A worker exports it to external storage. |
| epoch | A monotonically increasing number that identifies the active policy. It is kept only in `active_policy` and activation records and is not included in the PolicyBundle. It is not rewound on rollback. |
| standing rule | A pre-approved low-risk rule. It is defined in the policy data `data.standing_rules`, and matching requests are allowed without an ApprovalContract using a `standing_rule_id` and the session budget (`session_budgets`). |
| hold | A durable hold row in the `holds` table. It records the scope (global, node, workload, target, session), the reason, and the owning component that has the authority to release it. |
| dispatch permit | A short-lived execution permit issued to a specific attempt after checking current approval, policy, and health (TTL 10 seconds). |
| start permit | A permit that the node runtime bridge consumes for a specific container execution instance on a node where `startup_guard_gate` is active. It is separate from the dispatch permit. |
| `startup_guard_gate` | An independent gate that bundles the start guarantees before the first code runs (start permit consumption, runtime guard, wrapping of native start). It is turned on only for node/runtime combinations that passed Q0. |
| sensor generation | A server-managed version that distinguishes node/boot, sensor restarts, and hook/rule changes. When it changes, existing work readiness checks and start permits are invalidated. |
| node runtime bridge | A trusted component on the OCI/NRI start path (TASK-01/09/10). It consumes start permits. |
| application session bridge | The trusted runtime of TASK-15. After passing the required work start gate, it runs multiple session runners and submits actions with a session token. Its identity and permissions differ from those of the node runtime bridge. |
| Work start gate | An MVP-required contract that starts agent work after checking the readiness of observation, policy, and log collection for the node and the Pod, as well as session permissions and budget. It is different from blocking before the container ENTRYPOINT. |
| adapter transport recorder | A component inside the adapter process that records actual socket addresses and times to create an AdapterObservation (TASK-05). Its former name is "trusted adapter bridge". |
| high-water mark | The highest class among the data a session or workload has received so far. It is stored in `workload_data_state` and never decreases. |
| fail-closed | If a required check cannot be performed, new execution is not allowed. |
| fail-open | The target action proceeds even if the checking component fails. A fatal NRI plugin error falls into this category ([execution start guarantee contract](#execution-start-guarantee-contract)). |

## ID and terminology dictionary

The names on the left below are no longer used in documents or code. Documents that still contain an old name are corrected to the source of truth on the right.

| Old name or expression | Source of truth | Notes |
| --- | --- | --- |
| `policy_version` | `policy_bundle_id` + `policy_epoch` | Active state is compared by epoch, content by bundle digest |
| `reason_code` | `reason_codes` (array) | Values come only from the [reason code dictionary](#reason-code-dictionary) |
| `test_run_id` | `run_id` | Shared by regression test and measurement runs |
| `fixture_digest` | `fixture_set_digest` | Digest of the fixture set. Individual fixtures use `fixture_id` + content digest instead of `fixture_digest` |
| `baseline_digest` | `baseline_bundle_digest` | Regression test runner input |
| `observed_at` (AuditEvent, evidence) | `source_time` | Time at which the original source observed the fact (source clock). Server receive time is `received_at` |
| `owner_id` | `authenticated_actor` | Determined from the authentication context |
| `PreparedRequest` | `WirePlan` | Result of adapter `prepare()` |
| `approved_by` | `authenticated_actor` (user approval), `approved_by_actor` (policy change approval) | Distinguishes the two approvals |
| `max_uses` | `max_actions` | Number of logical actions |
| `catalog_version` (input to decisions and digests) | `catalog_digest` | `catalog_version` is kept only as a display label |
| `unknown_operation` | `ENDPOINT_NOT_REGISTERED` | Unsupported operation |
| trusted adapter bridge | adapter transport recorder | |
| runtime bridge (when used without distinction) | node runtime bridge / application session bridge | |
| `step_id` | Removed | The gateway issues the trace ([Normalization and hashing](#normalization-and-hashing)) |
| `active_policy.hold` | `holds` row (`reason = policy_activation`) | Boolean removed |
| `image_digest` (start binding) | `image_manifest_digest` + `image_id` | Distinguishes the Admission check value from the value exposed by CRI/OCI |
| exec linkage of `trusted adapter bridge` | `process_exec_id` on the kernel event side | No exec ID is placed in AdapterObservation |
| `/v1/policy-proposals` | `POST /internal/proposals` | The operator starts from an issue |
| `/internal/control-health/{workload_id}` | `GET /internal/control-health?scope=&scope_id=` | |
| `GET /test/v1/receipts/{receipt_id}` | `GET /test/v1/receipts/{action_id}` | The key name is `action_key` |
| `/internal/evidence/regressions/{test_run_id}` | `/internal/evidence/regressions/{run_id}` | |
| Decision signature | mTLS service connection + immutable decision row in the DB | |
| OPA sidecar, `127.0.0.1:8181`, Data API `?provenance=true` | The gateway's embedded OPA (`opa/v1/rego`) directly records the bundle manifest revision used for evaluation | The meaning of `opa_bundle_revision` is unchanged |
| httpcore `send_request_headers.started` | Go `httptrace.ClientTrace.WroteHeaders` | Boundary between `failed`/`unknown` |
| FastAPI, Pydantic, SQLAlchemy, Alembic, httpcore (Go components) | `net/http`, strict JSON decoding, `pgx`+`sqlc`, `golang-migrate`, `net/http.Transport` | Python components keep FastAPI, Pydantic, psycopg 3 |
| Python `rfc8785`, Python `json.loads` strict parsing | Go `packages/canonical/` | Python does not compute digests |
| Policy proposal service path (mixed earlier notations) | `services/proposer/` | |
| `receipts` table | `receiver.receiver_effects` | TASK-08 |
| `destination_observed.body_digest` | `wire_body_digest` | Body SHA-256 computed by the receiver |
| `model_thought_signatures` | `model_turns` | Stores the full original parts |
| `dispatch_queue` | `execute_requests` | The gateway's durable execute delivery table (TASK-04) |
| Direct regression runner call (`/internal/regression-runs` directly to the regression project) | Operations project `regression-dispatcher` + `regression-requests` and `regression-reports` buckets | [Regression test contract](#regression-test-contract) |
| workload SAN `spiffe://agentarium.internal/workload/<pod_uid>` | `spiffe://agentarium.internal/ns/<ns>/sa/<ksa>` (+ `/pod/<pod_uid>` for execution Pods) | [Service PKI](#service-pki-and-identifiers) |
| `data.targets` | `data.catalog.targets` | [Appendix A](#appendix-a-policy-data-and-patch-schema) |
| `data.standing_rules[]` (array), StandingRule `operation_id` | `data.standing_rules{id: rule}`, `operation_ids[]` | |
| `approval_snapshot.revoked`, lease `state` | `revoked_at`, `observed_state` | OPA input |
| `fixture_set_digest`, `include_holdout` in the regression request | `fixture_scope`, `extra_fixture_ids` (the runner returns the digest) | |
| KSA `test-receiver`, `lifecycle-watcher` | `receiver`, `pod-watcher` | [KSA and label rules](#service-pki-and-identifiers) |
| adapter constraint ConfigMap | `data.adapter_constraints` in the same bundle | |
| `Vertex AI` | Gemini Enterprise Agent Platform (Agent Platform for short) | Write "formerly Vertex AI" alongside it at first mention |

## Google technology usage design

### Connection between the evaluation criteria and the project

The evaluation criterion is **how concretely the problem in the domain was solved using Google technology**. In Agentarium, Gemini is used as **an agent that produces policy improvement proposals grounded in execution evidence**, and approval intent comparison and call path discovery are AI-assisted functions. The design examines user approval, gateway decisions, actual sends, target results, and kernel observations together, and distinguishes excessive policy allowance, blocking of required operations, and observation gaps. AI presents evidence, warnings, and proposed fixes, while enforcement controls and deployment approval are handled by the deterministic gateway, adapters, verifiers, and operating procedures.

Google Cloud announced on 2026-04-22 that "Vertex AI is now part of Gemini Enterprise Agent Platform" ([Agent Platform release notes](https://docs.cloud.google.com/gemini-enterprise-agent-platform/release-notes)). This document uses "Agent Platform" from here on. API service endpoints and IAM permission names are rechecked against the official documentation at installation time.

The following is the **MVP implementation contract**. It distinguishes the features provided by Google products from the flows the project must implement, and it does not mean that implementation, deployment, or measurement is complete.

### AI one-way principle

AI (Gemini) output is used only to make decisions stricter (`allow → approval_required`) or to produce warnings, annotations, and candidates shown to people. The following rules apply to all AI functions.

| Rule | Content |
| --- | --- |
| No allow creation | AI output cannot create `allow`, lower `deny` or `approval_required`, or create confirmed states such as catalog allowance, confirmed correlation (`confirmed`), or `effect_verified`. |
| Determinism retained on failure | If an AI call fails or times out, the function's `*_status` is recorded as `not_run` and the deterministic decision is used as-is. |
| Control path | All AI calls go through the model adapter and the `model.generate` operation. Per-function profiles (`policy_proposal`, `intent_check`, `discovery`, `agent`) set the request and output limits. |
| Input handling | External text, logs, and source code in the input are marked and delivered as data, not as instructions. |
| Regression invariant | "Zero cases in which AI output created an allow" (`ai_created_allow_count = 0`) is included in the `release_eligible` invariants. |
| Widening proposals | If a change built from model-proposed `builder_params` contains permission widening items (`permission_widening.items`), it is approved only if the approver acknowledges each item. If `widening_acknowledged_items` in the approval request is not equal to the full set of widening items, TASK-14 rejects the approval. Because AI-originated widening confirmed by a person in this way is not counted in `ai_created_allow_count`, it is counted and reported separately as `ai_proposed_widening_count`. |
### Technologies Used and Implementation Deliverables

| Google Technology | Role in Agentarium | Implementation Deliverables and Evidence to Verify | Linked Task |
| --- | --- | --- | --- |
| Gemini model API in Agent Platform | Analyzes approved evidence, selects evidence lookup tools, and writes and modifies policy change explanations | Tool call history, `PolicyProposal` with linked grounds, candidates before and after test feedback. Model calls route through the model adapter | [TASK-05](TASK-05-service-adapters.md), [TASK-12](TASK-12-policy-proposals.md), [TASK-15](TASK-15-runtime-integration.md) |
| Gemini function calling | Queries current policies, behavioral evidence, and regression test results in the required order | Verification that only registered read tools are executed, and evidence from other tenants and unregistered tools are rejected | [TASK-02](TASK-02-catalog-contracts.md), [TASK-05](TASK-05-service-adapters.md), [TASK-12](TASK-12-policy-proposals.md) |
| Gemini structured output | Returns proposals, intent checks, and discovery candidates as verifiable JSON | `responseMimeType`/`responseSchema` configuration and server re-verification results | [TASK-04](TASK-04-policy-gateway.md), [TASK-12](TASK-12-policy-proposals.md), [TASK-02](TASK-02-catalog-contracts.md) |
| Gemini approval intent check | Displays differences between user task descriptions and server-rendered approval contracts as warnings. Only escalates standing rule auto-allow to `approval_required` | `IntentCheckResult`, approval screen warnings and itemized acknowledge logs, `intent_divergence` issue | [TASK-04](TASK-04-policy-gateway.md), [TASK-03](TASK-03-identity-approval.md), [TASK-05](TASK-05-service-adapters.md), [TASK-13](TASK-13-regression-harness.md) |
| Gemini call path discovery | Generates network, file, and process call site candidates for version-pinned libraries and team-owned tools, and compares them with dynamic observations | `discovery_candidates` and reproduction traces, human-reviewed catalog registrations or blocked fixtures | [TASK-02](TASK-02-catalog-contracts.md), [TASK-13](TASK-13-regression-harness.md) |
| Google ADK (Python) | Demonstration agent runtime. Sends model calls to gateway `model.generate` | ADK tool wrappers, direct Agent Platform call/telemetry/auto-retry disablement configurations, NetworkPolicy blocking tests | [TASK-15](TASK-15-runtime-integration.md) |
| GKE Standard / Dataplane V2 | Deploys execution, control, adapter, and observability workloads and operates node sensors | Role-based deployment and network/RBAC/admission configurations and blocking tests, per-node/kernel sensor support and collection gaps | [TASK-01](TASK-01-gke-platform.md), [TASK-09](TASK-09-node-sensor.md), [TASK-15](TASK-15-runtime-integration.md) |
| Workload Identity Federation for GKE and IAM | Links Google API access permissions to service roles | Gemini access for model adapters, storage permissions for audit writers, denial of direct access for execution Pods. Authenticates without service account key files | [TASK-01](TASK-01-gke-platform.md), [TASK-06](TASK-06-egress-credentials.md) |
| Secret Manager | Provides service-specific credentials scoped to adapter requirements | Retrieval of only allowed secrets/versions, denial of retrieval for execution Pods, rotation and audit logs | [TASK-06](TASK-06-egress-credentials.md) |
| Cloud SQL for PostgreSQL | Stores approvals, reservations, attempts, and audit outbox within the same transaction | Approval limits for duplicate/concurrent requests, prohibition of sending prior to COMMIT, post-failure state recovery results | [TASK-03](TASK-03-identity-approval.md), [TASK-07](TASK-07-audit-store.md), [TASK-14](TASK-14-policy-release.md) |
| Cloud KMS | Signs GCS evidence manifests, and internal CA signing key if needed | `prev_manifest_digest` chain and signature verification results | [TASK-07](TASK-07-audit-store.md), [TASK-06](TASK-06-egress-credentials.md) |
| Cloud Storage (GCS) | Stores evidence, test reports, signed policy bundles, and checkpoints | Unlocked 30-day retention policy and soft delete, object references and writer permissions, linking reports with bundle digests | [TASK-07](TASK-07-audit-store.md), [TASK-13](TASK-13-regression-harness.md), [TASK-14](TASK-14-policy-release.md), [TASK-16](TASK-16-delivery-runbooks.md) |

**Additional Evaluation Candidates:** Google's Gen AI evaluation service can evaluate the groundedness of proposals and tool call paths. After checking the selected model, region, API/SDK, and Preview status, it will be introduced as an auxiliary evaluation in TASK-13. Even without adopting this service, fixed regression tests will be implemented, and model-based scores do not substitute for actual blocking and normal behavior verification or policy release conditions. [Official Evaluation Overview](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/evaluation-overview), [Agent Evaluation](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/evaluation-agents).
### Gemini evidence lookup and policy improvement flow

1. **Choose the improvement target.** The TASK-11 validator creates `issues` rows from mismatch, unknown, and gap (`POST /internal/issues`), and a divergent intent check result can also become an issue with `source = intent_divergence`. The operator starts a proposal with `POST /internal/proposals {issue_id}` (TASK-12). Original secrets and unnecessary personal information are not sent to the model.
2. **Obtain a service session.** The policy proposal service (`services/proposer/`) obtains a service session bound to `issue_id`, `candidate_id`, tenant, `tool_budget`, and TTL via `POST /internal/service-sessions` (TASK-03). Even when the operator also submits an `operator_patch`, evidence is looked up with the same session.
3. **Look up the needed evidence.** When Gemini returns the tool name and arguments of a function call, the proposal service validates them and submits an `evidence.*` operation to `POST /v1/actions` with the service session. The gateway and the evidence-reader adapter check permissions and then return the sanitized results of `/internal/evidence/*` (TASK-11), and the proposal service passes them to the model as a `functionResponse`. The model does not query the DB, the cluster, or the internet directly. This design connects the application responsibilities defined by [Google function calling](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/tools/function-calling) to the project's control flow.
4. **Preserve the thought signature.** During function calling, Gemini 3 models require the thought signature of the previous response to be sent back unchanged in the next request, and return a 400 error if it is missing. The official SDK handles this automatically, but when REST is called directly the application must handle it ([Thought signatures](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/thought-signatures)). Because this project calls REST directly, the model adapter preserves the `thoughtSignature` of the response part as an opaque value and includes it in the next request of the same conversation. This value is not put in general audit records or logs; it is kept, as the original response part, only in `model_turns`, which is dedicated to the model adapter.
5. **A deterministic builder produces the diff.** The model proposes only builder parameters, descriptions, and evidence links, and a deterministic builder produces the patch and the diff. The builder narrows existing permissions to the observed normal usage range (`policy.draft.create` only narrows), and patch kinds are limited to the allow list of [PolicyProposal](#common-data-structures) (including `policy.draft.create`). Sensor rule changes can be proposed only as a patch written by the operator in `operator_patch` of `POST /internal/proposals`, and the model cannot propose them. Every candidate goes through the [permission widening check](#permission-widening-check-permission_widening) in `packages/policydiff/`.
6. **Write a structured proposal.** After evidence collection, a separate final response step requests the `PolicyProposal` description fields with `responseMimeType=application/json` and a supported `responseSchema`. The server revalidates the schema, evidence permissions, base bundle, and allowed patches. The supported schema range is pinned based on [Google structured output](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/capabilities/control-generated-output).
7. **Compare with the same tests.** The TASK-13 runner first re-evaluates stored decision inputs against the baseline and candidate bundles with [decision replay](#decision-replay-decision_replay) (`decision_replay`), and then runs baseline and candidate E2E tests with the required per-scope fixture set pinned in `fixture_registry`. The model's `required_tests` can only add fixtures. Runs during iterative revision have `run_kind = regression` and do not include holdout. Holdout is included only in the `run_kind = candidate_final` run of the final candidate, and the regression report given to the model contains only holdout aggregates.
8. **Revise using failure feedback.** Sanitized test failures, normal impact, and missing evidence are passed to Gemini to revise the candidate. Limits follow the table below; exceeding a limit or an invalid proposal stops the flow without automatic deployment and is recorded.
9. **A human approves the exact change.** The operator creates a change by submitting the validated `proposal_id` and the `run_id` of the final run including holdout (`run_kind = candidate_final`) to `POST /v1/policy-changes`. A separate approver approves the patch, bundle digest, report digest, `fixture_set_digest`, and `permission_widening` result together, and acknowledges each widened item if there are any. TASK-14 performs deployment, activation check, revalidation, and rollback. Gemini is not given permission to write the active policy, deployment state, or approval records.

**Model budget and settings (policy proposal profile):**

| Item | Starting value | Notes |
| --- | --- | --- |
| Number of candidates | ≤ 2 | Including the initial proposal |
| Read tool calls per candidate | ≤ 6 | Enforced by the service session `tool_budget.read_tool_calls` |
| Model calls per candidate | ≤ 8 | 6 tool turns + 1 final + 1 schema fix. Enforced by `tool_budget.model_calls` |
| Total model calls | ≤ 16 | `tool_budget.model_calls.total_max` |
| Provider timeout per call | 30 seconds | Excludes tool execution time. Pinned by Q0 measurement |
| Total model time | 300 seconds | Excludes tool execution time. Pinned by Q0 measurement |
| Request limit | 64KiB | Size including the thought signature |
| `thinkingConfig`, temperature, `maxOutputTokens` | Pinned in the environment lock | Values decided in Q0 |
| `finishReason = MAX_TOKENS` | Treated as failure | `MODEL_OUTPUT_TRUNCATED` |

**Implementation contract for lookup tools:** The tools below are read operations to be newly implemented in TASK-02/05/11/12. There are no implementation files yet. IDs are resolved only within the caller's service identity and the issue/tenant scope linked by the server, and result size, fields, and call counts are limited.

| Tool the model requests | catalog operation | Allowed arguments | Sanitized information returned |
| --- | --- | --- | --- |
| `get_action_evidence` | `evidence.action.read` | `action_id` | Approval/action digest, decision, attempt, and target results, kernel correlation level, authorized evidence references, unknown reasons |
| `get_policy_bundle` | `evidence.bundle.read` | `bundle_id` | The base bundle digest for the improvement target and the allowed policy data and catalog contract |
| `get_regression_report` | `evidence.regression.read` | `run_id` | Candidate digest, per-case results, denominators, normal impact, missing evidence. Holdout as aggregates only |

Tool arguments do not accept URLs, SQL, shell, credentials, or caller identity. External text in tool results is analysis material and is not treated as new instructions or permissions. Arbitrary Rego, commands, or manifests from model output are not executed. Google authentication is performed with the model adapter's WIF identity, and hidden network calls and automatic tool execution by the SDK are not allowed.

### Agent runtime (Google ADK)

The demonstration agent is built with Python ADK (TASK-15). The agent tools wrap only `submit_action`, `poll_action`, and `request_approval(action_id)`. `request_approval` does not accept a summary written by the agent, and the user sees only the contract rendered by the server. The agent's model calls are sent to gateway `model.generate` through ADK's custom model extension point. The extension point was confirmed in the source: `BaseLlm.generate_content_async` is an abstract method, and `LlmAgent.model` accepts `Union[str, BaseLlm]` ([base_llm.py](https://github.com/google/adk-python/blob/main/src/google/adk/models/base_llm.py), [llm_agent.py](https://github.com/google/adk-python/blob/main/src/google/adk/agents/llm_agent.py), main branch). TASK-15 creates `GatewayLlm`, which subclasses `BaseLlm`. Whether the same interface holds in the ADK version to be pinned is rechecked after the version is pinned. Direct Agent Platform calls, telemetry, and automatic retries in ADK and google-genai are turned off, and even if that setting is missing, NetworkPolicy blocks direct egress from the exec Pod.

The `model.generate` profile for agents (`agent`) has request and output limits, per-message-part source labels (`user`, `tool_result`, `system`), and session-scoped standing rules, and its data class inherits the high-water mark of `workload_data_state`. For a `tool_result` part, the runtime does not insert the original content; it specifies `{"ref": "action_result", "action_id": …}`, and the model adapter fills it with the server-stored value. The caller does not send previous model responses. The caller sends the `conversation_id` and the `model_turn` ref of each previous turn. The adapter checks tenant, session kind, session ID, and current session validity, and inserts the raw parts at the specified positions. The format is in [appendix B](#appendix-b-modelgenerate-integration-contract). TASK-15 defines the `GatewayLlm` conversion rules (LlmRequest contents → `messages[]`, tools → `tool_declarations`, ADK tool results → `tool_result` references) and the handling of 202 `approval_required` (stop the turn with an `ApprovalPending` exception and poll) and 503 (fail the turn after 3 exponential backoff retries).
### Approval intent check (intent check)

Chapter 4 of the plan states that full semantic verification of free-form intent is not guaranteed. The intent check is a warning feature that supplements this gap and does not claim a guarantee.

| Item | contract |
| --- | --- |
| Component and ownership | `services/intent_check/` (TASK-04, including decision escalation). The model adapter's `intent_check` profile belongs to TASK-05, approval screen warnings and acknowledge storage to TASK-03, and fixtures and metrics to TASK-13 |
| When it runs | (1) For `approval_required` actions, TASK-03 calls `POST /internal/intent-checks` (TASK-04) before rendering `GET /v1/actions/{action_id}/approval-contract`; (2) before the decision is finalized, when an operation marked in the catalog with `intent_check_on_standing_rule = true` is allowed by a standing rule. `model.generate` calls from service sessions (including the intent check's own calls) are not covered |
| Input | The `task_statement` entered by the user at session creation and stored by the server, the structured display contract rendered by the server (target, disclosed fields, count, expiry, synthetic data content preview), and the catalog operation description. Text written by the agent is not included. External text inside the input is marked as data |
| Output | `IntentCheckResult` ([common data structures](#common-data-structures)). The server re-validates the schema, and a validation failure yields `intent_check_status = not_run` |
| Effect | `divergent` and `unclear` are shown as warnings on the approval screen, and the user must acknowledge each finding before approving (`INTENT_ACK_REQUIRED`). If `divergent` is returned for a request that would be allowed by a standing rule, the decision is escalated to `approval_required` (`INTENT_DIVERGENCE_ESCALATED`). `consistent` adds no permission. A `divergent` result can create `issues` (`source = intent_divergence`) |
| Call path | The intent checker submits `model.generate` (`intent_check` profile) to `POST /v1/actions` with its own service session. It goes through the same gateway and model adapter path as other AI calls |
| Request API | `POST /internal/intent-checks` (owner TASK-04, caller the TASK-03 contract renderer): `action_id, contract_digest, rendered_contract` → IntentCheckResult. The standing rule path is an internal gateway call |
| Time limit | On the standing rule path, `POST /v1/actions` processing waits synchronously for up to 3 seconds (to be fixed by Q0 measurement). If exceeded, the result is `not_run` and the deterministic decision is used as is. The intent checker's service session budget is one model call |
| Event | `intent_checked` |
| Demo link | If the user requested "send only the summary" and the contract contains an email field, a `field_extra` warning is raised, and this result becomes an `intent_divergence` issue that serves as the starting evidence for the policy improvement flow |

### Call path discovery (discovery)

Produces the input that fills the visibility denominator in chapter 3 of the plan ("finalize the list of calls, SDK automatic retries, and redirects used by initial work"). The methodology cites REA (https://rea.tools/) only as reference material.

| Item | contract |
| --- | --- |
| Ownership and location | TASK-02 (candidate storage and promotion procedure); dynamic execution reuses the TASK-13 harness. The analyzer runs outside the execution area (`agent-observe` or the regression test project) |
| Targets | Version-pinned libraries used by the runtime and adapters (ADK, google-genai, google-auth, httpx, Go `net/http`, `golang.org/x/oauth2`, etc.) and team-owned tools. Only open-source, license-permitted targets are covered; internals of external SaaS and proprietary binaries are excluded |
| Static analysis | `POST /internal/discovery/runs` starts the analyzer (`services/discovery/`). The analyzer uses only `model.generate` (`discovery` profile) and read tools, with a discovery service session (`snapshot_id` scope). The read tools are `discovery.source.read` (`GET /internal/discovery/snapshots/{snapshot_id}/files`, arguments `path, start_line, end_line`) and `discovery.callgraph.read` (`GET /internal/discovery/snapshots/{snapshot_id}/callgraph`, argument `symbol`, depth 3 or less), and responses are 64KiB or less. Paths outside the pinned snapshot are rejected |
| Dynamic observation | Fixed scenarios are run with controls on/off in the analysis environment of the regression test project (`run_kind = discovery`), and kernel sensor traces are compared with adapter records |
| Matching | A deterministic matcher matches the `destination_template` (scheme + host glob + path prefix) of static candidates against dynamic observations and classifies them as `observed_not_static`, `static_not_observed`, or `matched`. Both the control-on and control-off arms are matched, and the arms in which a candidate was reproduced are recorded as `matched_arms`; observations of Agentarium infrastructure destinations do not create new candidates. Gemini only attaches explanations to the classification results. TASK-02 defines the template syntax, the snapshot generation tools (the Python `ast` call-site scanner and Go `golang.org/x/tools/go/callgraph/vta`), and the API body |
| Promotion | AI output alone cannot register anything in the catalog or allow it. After a candidate is reproduced in a dynamic trace (`reproduced`) and reviewed by a human, it is promoted (`promoted`) to a catalog operation registration (allow) or to a forbidden fixture or SDK configuration verification item (deny or disable). An `observed_not_static` candidate found only through observation is treated as reproduced, but it cannot be promoted to an allow; it can be promoted only to a forbidden fixture or SDK configuration verification item |
| Events | `discovery_candidate_recorded`, `discovery_candidate_promoted` |

### One demonstration to show in the evaluation

In a **test environment that uses only synthetic data**, the business requirement "only the summary must be sent to the receiving service" is fixed, and the initial policy intentionally contains a flaw that also allows a synthetic email field. The presentation and report state that this flaw and the regression case are **cases planted in advance** for the demonstration. Because the approval contract also reflects the initial broad scope, this case is distinguished from tampering with an approved body. The intent check warns about the difference between the user's task description and the contract, and Gemini queries the requirement, the initial policy, and the actual receipt evidence to point out the excessive permission. The deterministic builder produces a patch that narrows `receiver.allowed_disclosure_fields` to `["summary"]`, and Gemini attaches an explanation of the evidence.

| Policy | Request including email | Request including only the summary |
| --- | --- | --- |
| baseline (flawed) | gateway `allow` (flaw reproduced) | `allow`, receipt effect confirmed |
| candidate | gateway `deny`, `DISCLOSURE_SCOPE_DENIED` | `allow`, receipt effect confirmed |

The holdout contains at least one case that cannot be passed with simple field name matching (for example, a `summary` that contains a synthetic email pattern inside an allowed field, with `CONTENT_PATTERN_DENIED` expected). On failure, Gemini reads the report and revises the candidate; after a human approves the exact candidate that passed, the demo shows deployment, re-verification, and rollback. Cases with missing observations remain unknown, and empty evidence is not filled in with model explanations.

<a id="measurement-and-tracing-contract-ref"></a>

### Measurement and tracing contract

Every ratio is reported together with its numerator, denominator, and a Wilson or Clopper-Pearson 95% interval. p95 is computed only when the defined request set has 100 or more requests; with fewer, it is marked "insufficient sample". Numeric targets are null until finalized and are not used in gates. TASK-13 `packages/evaluation` owns the implementation definitions of numerators and denominators.

| Item to check | Recording and comparison method |
| --- | --- |
| Grounded proposals | Number of references with valid permissions and versions / total number of references, and whether the evidence supports each claim as confirmed by a human. The fact that a reference exists is kept separate from the judgment that it supports the claim |
| Executable changes | Number of candidates that passed server schema, patch scope, and baseline bundle validation / total number of candidates, and rejection reasons |
| Decision replay | Number of replays in `decision_replay`, number of requests whose decisions changed, and differences in reason rules (`matched_rule_ids`). This is evidence of normal-traffic impact, not a gate |
| Permission widening | Whether `permission_widening.widened` is set, the number of widened items, and acknowledge records |
| Actual policy improvement | Per-case 2×2 results of baseline/candidate with the same `fixture_set_digest` (baseline result vs. expectation × candidate result), the number of cases whose results changed, the number of forbidden effects, the number of normal successes, and the number of unknowns |
| Effect of using Google AI | On the same separate evaluation cases, compare a single-generation baseline against the tool query and test feedback flow. Input permissions and test criteria are kept identical |
| Control effect comparison group | Compare the number of forbidden effects, number of normal successes, and latency between a run with controls disabled (control-off baseline) and a run with controls |
| Operating cost | Model tokens, number of calls, call latency, audit storage latency and backlog, and number of approvals. Monetary amounts are computed only when usage and the applicable unit price are confirmed |
| intent check | Number of detected divergences / number of injected divergences, number of warnings on consistent cases (false positives), number of additional approvals caused by escalation, added latency p50/p95, and number of `not_run` |
| discovery | Number of candidates, ratio of candidates reproduced dynamically, number of dynamic observations not found statically, number of promotions (allow/deny), and number unresolved. The visibility denominator report separately marks "the scope confirmed by the discovery procedure" |

**`release_eligible` invariant:** Decided only by the following 0/1 conditions: zero forbidden effects, zero duplicate effects, zero unapproved activations, `ai_created_allow_count` of 0 ([formula](#regression-test-contract)), the deterministic decision is kept in intent check failure cases, all required fixtures pass, and required hook coverage (all required rows of the support table are observed).

For each model run, the following are recorded: model ID, region, API version, prompt template/tool declaration/output schema digests, the provider request ID and usage when provided, the action/attempt IDs corresponding to tool calls, references to sanitized inputs and results, and the candidate's parent ID and test report digest. These make it possible to trace **which evidence was viewed, which change was proposed, and which test, approval, and deployment it led to**. Secrets, sensitive raw text, thought signatures, and the model's private reasoning are not stored in general logs. Unmeasured scores, success rates, and costs are recorded as null.

## Trust Boundaries and Lifecycle

1. A user creates a session from the console via `POST /v1/sessions` by specifying a target `workload_id` and `task_statement`. The server issues a one-time `claim_code` (TTL 60 seconds). The runtime polls `GET /v1/runtime/assignments` via workload mTLS and receives a session token bound to the workload identity via `POST /v1/sessions/{session_id}:claim`. All ingress to the exec Pod remains completely blocked. User IDs, session_ids, data classifications, and traces sent by the agent are not treated as evidence of authorization.
2. The gateway normalizes into a catalog and trust state, and OPA makes an evaluation. `allow` is neither consumption of approval nor completion of transmission. The gateway does not make reservations.
3. If `allow`, the gateway selects an `adapter_id` via catalog binding, inserts an `execute_requests` row in the same transaction as the evaluation, and returns 202 and an `action_id` to the runtime. The gateway worker forwards `POST /internal/adapter/{adapter_id}/execute`. The runtime polls `GET /v1/actions/{action_id}` and `/result`.
4. The adapter creates a `WirePlan`, cross-checks the digest, evaluation, approval, and active bundle via preflight, and requests a reservation from the dispatch coordinator (TASK-03).
5. In the **same DB transaction**, it verifies epoch, hold, session, and approval/session budgets, reserves the logical action, and records attempt, `attempt_planned` audit event, and outbox. External transmission is prohibited before COMMIT confirmation.
6. The adapter receives credentials, claims the dispatch permit, and transmits while enforcing destination, TLS, and content. A crash/timeout after reservation may have remote effects.
7. Target and optional kernel evidence are cross-checked. Insufficient evidence is unknown/unconfirmed connection.
8. It proceeds via policy proposal → regression testing → separate human approval → signed immutable bundle deployment → active verification → revalidation/rollback.

A single Pod accommodates multiple logical sessions. Because session credentials in shared files/memory can be exfiltrated, strong isolation between adversarial sessions or complete impersonation prevention is not claimed. If the origin and blast radius cannot be narrowed down, it is held at workload scope. For traces, the gateway issues an internal W3C trace context, and `traceparent` and `baggage` sent by the runtime are stripped without being used as authorization evidence. The adapter does not forward internal trace headers to external destinations.

## Common Data Structures



### Actions, approvals, and decisions

| Structure | Required fields/rules |
| --- | --- |
| ClientAction | `session_id, operation_id, requested_target, arguments, client_request_key`. The typed schema of `requested_target` and `arguments` per operation (Go struct + JSON Schema, with valid and invalid examples) is owned by TASK-02. `client_request_key` is `[A-Za-z0-9_-]{8,64}`. actor, data_class, version, and `pod_uid` are not sent by the client; the server sets them |
| ActionEnvelope | `schema_version, action_id, request_id, authenticated_actor, session_kind, session_id, workload_id?, endpoint_id, operation_id, canonical_target, environment, tenant, disclosure_fields, data_class, data_sources, content_digest?, content_ref?, bytes, limits, catalog_digest, catalog_version, canonicalization_version, raw_body_digest, action_digest`. `canonical_target` always has `target_id, route_id` and adds operation-specific fields (logs: `namespace, pod_name, container`). `workload_id` exists only for user sessions and is null for service sessions. `environment` is a gateway installation setting. The key list of `action_digest` is in [Canonicalization and hashing](#normalization-and-hashing) |
| ApprovalContract | `approval_id, action_id, revision, approval_kind, authenticated_actor, session_id, contract_digest, displayed_contract_digest, allowed_operation, canonical_target, disclosure_fields, content_digest?, max_actions, used_actions, policy_epoch, expires_at, contract_version, revoked_at?, revoke_reason?, intent_check_id?, acknowledged_findings`. `approval_kind = action`, `max_actions = 1` (not a user-requested field). The gateway finds the latest unexpired, unrevoked revision by `action_id`. `pod_uid` is not included |
| ContractView | Server-rendered display contract JSON: `{contract_version, action_id, operation_id, operation_label, target {target_id, label}, disclosure_fields[], content_preview?, max_actions, expires_in_seconds, environment, tenant}`. Expiry is displayed as a relative duration, not an absolute time. `contract_digest` = canonical digest(ContractView JSON). The console sends back the digest of the view it displayed as `displayed_contract_digest`, and the server recomputes and compares it. Renderer owner: TASK-03 |
| StandingRule | policy data `data.standing_rules{<standing_rule_id>: rule}`: `standing_rule_id, session_kind(user/service), profile?, operation_ids[], target_pattern, disclosure_fields?, limits, data_profile?, session_budget`. `target_pattern` is a glob (separator `/`) over `canonical_target.target_id`. For the initial rules, the JSON in [Appendix A](#appendix-a-policy-data-and-patch-schema) is the source of truth |
| GatewayDecision | `decision_id, request_id, action_id, action_digest, adapter_id?, verdict, reason_codes, decision_basis?, approval_id?, standing_rule_id?, service_session_id?, activation_probe_id?, intent_check_id?, matched_rule_ids[], evaluated_rule_ids[], rego_result {verdict, reason_codes, matched_rule_ids}, gateway_added_rule_ids[], decision_stage, decision_input_ref?, decision_input_digest?, policy_bundle_id, policy_epoch, opa_bundle_revision, catalog_digest, catalog_version, expires_at, authenticated_gateway`. `decision_input_ref` and `decision_input_digest` are null when `decision_stage = normalize`. The rules are in [Policy decision contract](#policy-decision-contract) |
| DecisionInput | `decision_inputs(decision_input_digest PK, tenant, sanitized_input jsonb, policy_bundle_id, created_at)`. Retained 30 days, owner TASK-04. Secrets, raw logs, and raw content are not included; only `content_digest` is included. `decision_input_ref = decision_input_digest`. Because several decisions can point to the same row, retention deletion happens only after every referencing decision is older than 30 days |
| IntentCheckResult | `intent_check_id, action_id, session_id, contract_digest, task_statement_digest, model_id, prompt_template_digest, intent_check_status(completed/not_run), overall?(consistent/divergent/unclear), findings[] {finding_id, kind, contract_path, user_text_span {start, end}, severity(low/medium/high), explanation}, findings_digest, not_run_reason?` |
| DispatchPermit | `permit_id, decision_id, action_id, request_id, attempt_id, reservation_id, adapter_id, action_digest, wire_body_digest, policy_epoch, catalog_digest, expires_at, claimed_at?` |
| WirePlan | `method, origin_id, route, safe_headers, body_bytes, wire_body_digest, response_limit, timeout, expected_tls_name, expected_uri_san?, allowed_cidrs`. `expected_uri_san` exists only when the target has `ca_ref = agentarium-trust` (TASK-02 Appendix A, TASK-05 3.2). `safe_headers` includes `Idempotency-Key` (value is `action_id`) and `X-Agentarium-Attempt-Id`. Authorization is added at the credential stage and excluded from digests and audit. Go `net/http` writes Host and Content-Length automatically and inserts `Go-http-client/1.1` if User-Agent is absent ([net/http](https://pkg.go.dev/net/http)). Therefore User-Agent is set explicitly, automatic `Accept-Encoding` is suppressed with `DisableCompression: true`, and the identity claim is limited to "body bytes identical". Total header size is limited to 2KiB or less (TASK-05), and the `failed`/`unknown` boundary is `httptrace.ClientTrace.WroteHeaders` ([Failure classification](#failure-classification)) |
| AdapterObservation | `attempt_id, request_ordinal, request_role, local_addr, local_port, peer_addr, peer_port` (getsockname/getpeername), `netns_inode` (`/proc/self/ns/net`), `dialed_addr, peer_addr_kind(service_vip/endpoint/external), pod_uid, connect_started_at, send_started_at, send_finished_at, response_at, provider_request_id?, k8s_audit_id?` (response header `Audit-Id`), `wire_body_digest?`. `dialed_addr` is the address chosen by DialContext. One is created per sub-request, and `request_ordinal` (starting at 1) distinguishes the sub-requests. A single-call adapter creates only one, with `request_ordinal = 1` and `request_role = primary`. They are delivered as `observations[]` in the outcome API and stored in TASK-03 `attempt_observations` per `(attempt_id, request_ordinal)`. `process_exec_id` is not included |
| AdapterExecution | `adapter_executions(decision_id PK, action_id, adapter_id, state(received/preflight_rejected/reserved/completed/failed), attempt_id?, updated_at)`. Idempotency key for execute. Owner TASK-05 |
| ActionResult | `action_id, attempt_id, execution_state, data_class, result_body (sanitized), truncated, truncation_reason?, evidence_level, result_digest, created_at`. The adapter writes it to `action_results`, and the gateway serves it via `GET /v1/actions/{action_id}/result` |
| ModelTurn | `model_turns(conversation_id, turn_index, tenant, session_kind, session_key, action_id, raw_parts jsonb, created_at, expires_at, PRIMARY KEY(conversation_id, turn_index))`. `session_key` is the user `session_id` or the `service_session_id`, and conversations of different `session_key`s are not concatenated. The raw parts of model responses (including thought signatures) are kept as is. It is exclusive to the model adapter, and other roles cannot read it. The former name `model_thought_signatures` is not used |
| ActionContent | `content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at (30 days)`. The key is `(content_digest, action_id)`. Even if several actions have the same content, each action has its own row. The gateway writes it, and only the corresponding adapter and the TASK-03 contract renderer (content preview) read it. It is not included in the audit `safe_payload`. The adapter recomputes the digest of the raw content it read and compares it |
| WorkloadDataState | Key: `(workload_id)` for user sessions, `(service_session_id)` for service sessions. Fields `data_class_high_water, data_sources, updated_by_attempt_id, updated_at`. The adapter updates it with `GREATEST` using the response's `response_data_class` (TASK-05), and the gateway reads it as OPA input. If there is no row, it is `none`. Postgres enum order `none < synthetic < internal < confidential` |
| CatalogOperation / CatalogTarget | The source of truth for YAML fields, JSON Schema, and examples is the TASK-02 appendix. Fields that COMMON depends on: for operations, `operation_id, endpoint_id, adapter_id, route_id, limits, disclosure, response_data_class, redact_fields[], intent_check_on_standing_rule, model_profiles?, description`; for targets, `target_id, endpoint_id, environment, tenant, origin, expected_tls_name, allowed_cidrs, max_data_class, operation_ids`. The bundle's `data.catalog` is a map keyed by id (`data.catalog.operations[operation_id]`, `data.catalog.targets[target_id]`, `data.catalog.catalog_digest`) |
| Session | `session_id, authenticated_actor, tenant, workload_id, task_statement, requested_scope {operation_ids[], target_ids[]}, allowed_operation_ids[], state, claim_code_digest, claim_expires_at, claimed_workload_identity?, token_digest?, expires_at`. At creation, the server computes `allowed_operation_ids` as `requested_scope.operation_ids` ∩ the catalog operations that the workload role can use, and stores it. The default lifetime of 30 minutes is `expires_at` and is separate from the OIDC login session. `token_digest = SHA-256(token)` |
| ServiceSession | `service_session_id, caller_principal, authenticated_actor, profile, tenant, issue_id?, candidate_id?, change_id?, snapshot_id?, action_id?, tool_budget, state(active/expired/revoked), token_digest, expires_at`. `authenticated_actor` is `service:<namespace>/<ksa>` (the ns/sa in the caller certificate SAN), and this value is also used for `authenticated_actor` in ActionEnvelope and AuditEvent. Only one scope is chosen. Allowed operations, budget, and TTL per profile are in the [service profile table](#service-profiles) below, and the budget sent by the caller is clipped to this upper bound. Only one active session is kept per candidate (`issue_id`, `candidate_id`). If an active session exists, the request is rejected with `SERVICE_SESSION_ACTIVE`. After the previous session expires or is revoked, a new session can be created again for the same candidate. The candidate's cumulative usage exists only in one row per counter in `issue_candidate_counters`, and recreated sessions share this row. The per-session `service_session_counters` row holds that session's upper bound (`max_value`) and the count used by that session (`used_value`, starting at 0). On recreation, the previous session's usage is not copied. The coordinator consumes this candidate row on reservation and restores it on released. If the applied upper bound is less than the cumulative usage, the request is rejected with `TOOL_BUDGET_EXHAUSTED` |
| ToolBudget | The structure of ToolBudget is split in two according to the ServiceSession `profile`. The ToolBudget of `intent_check`, `policy_proposal`, and `discovery` sessions is `{read_tool_calls: {per_candidate_max, used_by_candidate}, model_calls: {per_candidate_max, total_max, used_by_candidate, used_total}, candidates: {max, used}}` and has no `probe_actions` key. The ToolBudget of `activation_probe` sessions is `{probe_actions: {max, used}}` and has no other keys. `probe_actions.max` equals the `max_value` stored in that session's `service_session_counters.probe_actions` row, and `used` equals `used_value` of the same row. `evidence.*` and `discovery.*` are counted as read tools, and `model.generate` is counted separately as a model call. When a new `candidate_id` is used for the first time, `candidates.used` is incremented by 1. The coordinator consumes it in the reservation transaction, and when exhausted, `TOOL_BUDGET_EXHAUSTED` |
| SessionBudget | `session_id, standing_rule_id, max_actions, used_actions, expires_at`. Budget for requests allowed by a standing rule. The upper bound is `data.standing_rules[].session_budget` in the bundle, and the coordinator reads it from the active bundle |
| ActivationProbe | `activation_probes(activation_probe_id PK, change_id, service_session_id, client_request_key, action_id?, target_epoch, expires_at, UNIQUE(service_session_id, client_request_key))`. Registration happens before submission, and the gateway fills `action_id` on submission ([Activation probe dedicated dispatch](#activation-probe-only-dispatch)) |
| CredentialBinding | `credential_bindings(credential_binding PK, adapter_id, operation_id, secret_resource, secret_version, header_name, header_format, enabled, updated_at, updated_by)`. One binding corresponds to one operation. Owner TASK-06. Version updates follow the operator procedure (TASK-16 runbook) |
| RegisteredWorkload | `registered_workloads(namespace, ksa, role, adapter_id?, service_principal, PRIMARY KEY(namespace, ksa))`. Owner TASK-03. The principal and adapter_id are looked up by the ns/sa in the certificate SAN |
#### Service profiles

This is a server-side table owned by TASK-03. Rego `service.scope_allow.v1` decides service session requests using this table (policy data `data.service_profiles`).

| profile | caller | scope | Allowed operations and targets | Budget limit | TTL |
| --- | --- | --- | --- | --- | --- |
| `intent_check` | TASK-04 intent checker | `action_id` | `model.generate` (`intent_check` profile) | 1 model call | 30 seconds |
| `policy_proposal` | TASK-12 proposal service | `issue_id` (+`candidate_id`) | `evidence.action.read`, `evidence.bundle.read`, `evidence.regression.read`, `model.generate` (`policy_proposal`) | Per candidate 6 read tool calls and 8 model calls, 2 candidates, 16 model calls in total | 15 minutes |
| `discovery` | TASK-02 discovery analyzer | `snapshot_id` | `discovery.source.read`, `discovery.callgraph.read`, `model.generate` (`discovery`) | 50 snapshot reads and 20 model calls | 30 minutes |
| `activation_probe` | TASK-14 releaser | `change_id` | Only requests allowed by the `probe.activation.v1` standing rule | 4 per activation attempt. The releaser creates a new service session for each activation and each rollback, so a rollback gets a separate 4 | 10 minutes |

<a id="audit-observation-and-health-ref"></a>

### Audit, observation, and health

| Structure | Required fields/rules |
| --- | --- |
| AuditEvent | `event_id, event_type, tenant, source_id, source_version, source_epoch, source_sequence?, source_time, received_at, schema_version, authenticated_actor?, workload_id?, session_id?, action_id?, request_id?, attempt_id?, policy_bundle_id?, policy_epoch?, catalog_digest?, catalog_version?, payload_digest, evidence_refs, safe_payload`. `event_type` allows only values from the [event_type registry](#event_type-registry). `source_epoch` distinguishes each new run of the producer process, so it tells apart a `source_sequence` that restarted because of a process restart. The durable restart counter rule for work producers is kept, and the lifecycle encoding follows [Lifecycle source authentication and epoch](#lifecycle-source-authentication-and-epoch). `source_sequence` starts at 1 for each epoch. `payload_digest` = JCS SHA-256 of all remaining fields excluding `payload_digest` and `received_at` |
| KernelEvent | `source_event_id, sensor_id, source_epoch, source_sequence, exporter_instance_id, sensor_generation, node_uid, boot_id, source_time, spooled_at, process_exec_id?, parent_exec_id?, process_start?, host_pid?, container_id?, docker_id_prefix?, pod_uid?, netns_inode?, socket_tuple?, sock_ptr?, tcp_new_state?, lifecycle_record_id?, metadata_status, normalization_version, upstream_event_ref?, event_type, safe_attributes, rule_hash, coverage, record_digest`. `received_at` exists only in the storage/query model and is not included in requests. `record_digest` is the JCS SHA-256 (64 lowercase hex characters) of the entire record excluding itself and `received_at`. `process_exec_id` is required only for event_types that have a process context (`process_exec`, `process_exit`, `tcp_connect`, `file_open`, `openat`), and may be null for `tcp_state` (a state transition in softirq context). When observed, `sock_ptr` is a 16-character lowercase hex string (`^[0-9a-f]{16}$`, no `0x` prefix) and is not sent as a JSON integer. `tcp_new_state` is a JSON integer required for `tcp_state`, and uses the `TCP_ESTABLISHED(1)` and `TCP_CLOSE(7)` values that the TASK-09 policy observes. Both fields are top-level fields, not part of `safe_attributes`. TASK-07 owns the table of required fields per event_type. Storage is a separate table `audit.kernel_events` (`UNIQUE(source_id, source_epoch, source_sequence)`, an index for socket tuple lookup), and the events are not inserted again into `audit_events`. `source_event_id` = UUIDv5 (namespace constant in `packages/canonical/`, name `sensor_id/source_epoch/source_sequence`). Tetragon events have no cgroup ID, so cgroup linking is done through LifecycleRecord. `docker_id_prefix` (the Tetragon `docker` field, 15 characters) is an auxiliary key. The `KprobeSock` cookie is not compared with the userspace `SO_COOKIE`. session_id is not inferred and filled in |
| LifecycleRecord | `lifecycle_event_id, source_id, source_epoch, source_sequence, cluster_uid, pod_uid, namespace, pod_name, node_uid?, boot_id?, container_id?(full ID), cgroups_path?, cgroup_inode?, container_name?, restart_instance?, image_id?, image_manifest_digest?, transition, source_time?, received_at, resource_version?, mapping_version, evidence_refs, missing_reason?, record_digest`. `received_at` exists only in the storage/query model and is not included in requests. `record_digest` is the JCS SHA-256 (64 lowercase hex characters) of the entire record excluding itself and `received_at`. The cgroupsPath, cgroup inode, and full container_id are recorded at create time. A `transition` from the pod-watcher source uses only four values: `pod_snapshot` (a Pod seen in the initial LIST), `pod_added`, `pod_modified`, and `pod_deleted` (WATCH events); `pod_deleted` is not interpreted as runtime termination, and `pod_snapshot` is not interpreted as process creation. `mapping_version` is the version of this source mapping rule and starts at 1 (separate from the TASK-10 interval revision). If the time of occurrence is unknown, `source_time` is null and is not filled with `creationTimestamp`. If there is no persistent external reference, `evidence_refs` is an empty array. Records are stored in a separate `lifecycle_events` table and are not inserted again into `audit_events`. `lifecycle_event_id` is also UUIDv5 (same namespace rule). `audit_outbox` distinguishes the source table with the `record_kind` column (`audit_event`, `kernel_event`, `lifecycle_event`). In the registry, `kernel_event_observed` and `lifecycle_recorded` are the kinds of the `kernel_events` and `lifecycle_events` rows respectively |
| WorkReadinessCheck | `check_id, work_run_id, checkpoint, session_id, workload_id, caller_identity, runtime_process_epoch, worker_instance_id, worker_binding_id, root_exec_id?, worker_evidence_refs[], instance_binding?, sensor_generation?, rule_hash?, policy_epoch?, challenge_id?, challenge_evidence_refs[], state(pending/ready/blocked/expired), reason_codes[], created_at, checked_at?, expires_at?, audit_event_ref`. instance_binding is `cluster_uid, pod_uid, node_uid, boot_id, container_id, restart_instance, cgroup_inode, image_manifest_digest` and is determined from the server-side lifecycle. Owned by TASK-10; ordering and expiry follow the [work startup contract](#agent-work-startup-contract) |
| SessionProcessBinding | `worker_binding_id, worker_instance_id, session_id, workload_id, caller_identity, runtime_process_epoch, supervisor_process_hint, worker_process_hint, isolation_profile_digest, controls_report_ref, registration_digest, instance_binding?, root_exec_id?, host_pid?, process_start?, exec_event_ref?, node_evidence_ref?, sensor_generation?, state(pending/observed/closed/invalidated), registered_at, observed_at?, ended_at?, reason_codes[], audit_event_ref`. The hints are the local PID, PID namespace inode, and `/proc/<pid>/stat` start ticks, and they are not evidence of permission or observation. Owned by TASK-10. `observed` is the state in which a trusted supervisor registration, an independent node witness, and a kernel exec DB COMMIT all exist; current liveness and work authorization are rechecked separately in readiness |
| KernelSessionAttribution | `kernel_event_id, worker_binding_id?, session_id?, status(linked/unlinked), method(root_exec/process_lineage/none), evidence_refs[], algorithm_version, revision, reason`. A separate derived table of TASK-10. It does not inject session_id into the original KernelEvent and does not promote the existing action/attempt Correlation.confidence |
| StartPermit | `start_permit_id, start_attempt_id, cluster_uid, pod_uid, container_id, container_name, restart_instance, image_manifest_digest, image_id, node_uid, boot_id, bridge_identity, sensor_generation, guard_generation, rule_hash, runtime_profile_digest, binding_digest, check_snapshot_id, lifecycle_record_id, issued_at, expires_at, consumed_at?`. Used only on nodes where `startup_guard_gate` is active |
| StartAttempt | `start_attempt_id, binding_digest, start_permit_id?, state, prepare_event_id, consume_event_id?, start_requested_event_id?, runtime_result_event_id?, exec_event_ref?, exit_event_ref?, failure_reason?, evidence_refs`. The allowed transition table is in [TASK-10 3.5](TASK-10-correlation-health.md#35-startup-state-identity-and-retry-implementation) |
| ObservationGap | `gap_id, stage, reason, node_uid?, boot_id?, source_epoch?, sequence_range?, range_digest?, start_at, end_at?, affected_workloads, loss_count?, count_quality, evidence_refs, recovery_state`. If the content, count, or time of the loss is unknown, keep null/unknown. `stage`, `reason`, and `recovery_state` use only the values and allowed combinations in the [enum definitions](#enum-definitions). A collection gap in network policy logs is recorded as `stage = network_policy_log`, and `end_at` must be present unless `recovery_state = open`; the creation, merge, and recovery rules and the computation of `affected_workloads` are in [TASK-10 3.7](TASK-10-correlation-health.md#37-network-policy-records-and-composite-decisions) |
| Correlation | `correlation_id, kernel_event_id, action_id?, attempt_id?, request_ordinal?, workload_id?, confidence, method, evidence_refs, candidate_count, algorithm_version, revision, reason, limitations`. `confirmed` only when the `(netns_inode, 4-tuple, pod_uid, time interval)` of a kernel connect/state event uniquely matches one row of `attempt_observations` (`(attempt_id, request_ordinal)`). The tuple normalization rules (Service DNAT, whether Dataplane V2 socket LB applies) are measured and fixed in Q0 |
| NetworkPolicyRecord | `record_id, cluster_uid, node_uid, source_epoch, source_sequence, node_name, source_time, received_at, disposition, direction, protocol, src_ip, src_port?, dest_ip, dest_port?, src_endpoint?, dest_endpoint?, policies[]?, count, normalization_version`. One entry of the GKE Dataplane V2 network policy log (`policy-action`), which the node collector reads from the node file and sends (TASK-06 3.4). `src_endpoint` and `dest_endpoint` are `{namespace?, pod_name?, workload_name?, workload_kind?, instance?}`, and `policies[]` is `{name, namespace}` and is present only on records with `disposition = allow`. `source_time` is the log entry's `timestamp`, and `received_at` is the time the linker stored it. `source_epoch` and `source_sequence` are sequence numbers attached by the node collector. `record_id` = UUIDv5 (namespace constant in `packages/canonical/`, name `cluster_uid/node_uid/source_epoch/source_sequence`). A record with `disposition = deny` groups identical `(src_ip, dest_ip, dest_port, protocol, direction)` within a 5-second window into one entry, so `count ≥ 1`, and `src_port` is not used as a match condition. For `icmp`, the port is null. TASK-10 stores them in `correlation.network_policy_records`, and they are not inserted again into `audit_events`. A Pod UID or `session_id` that is not in the log is not inferred and filled in. The absence of a log is not used as evidence that no attempt occurred |
| NetworkFinding | `finding_id, kind, outcome, network_segment, boundary_crossing, workload_id?, pod_uid?, node_uid?, kernel_event_ids[], policy_record_ids[], window_start, window_end, attempt_count?, count_quality, confidence, rule_version, algorithm_version, revision, reason, limitations[], created_at`. `created_at` is the DB time at which that revision was stored, and the timeline uses only revisions with `created_at ≤ evaluation_time`. A derived judgment combining kernel connection events and NetworkPolicyRecords; the rules are in [TASK-10 3.7](TASK-10-correlation-health.md#37-network-policy-records-and-composite-decisions). `kind`, `outcome`, `network_segment`, and `boundary_crossing` use only values from the [enum definitions](#enum-definitions). `confidence` uses only `workload_inferred` and `unlinked`. An aggregated record cannot prove a unique match to an individual attempt, so `confirmed` is not provided. `session_id` and `action_id` are not included, and the `confidence` of an existing Correlation is not promoted. The original KernelEvent and NetworkPolicyRecord are not modified. A late record adds a revision to the same `finding_id` and preserves the previous judgment. TASK-10 stores them in `correlation.network_findings` |
| Hold | `hold_id, scope, scope_id, reason, reason_detail?, owner_component, created_at, released_at?, release_ref?`. `reason` is the list of reasons in the [enum definitions](#enum-definitions). `reason_detail` is present only when `reason = risk_event`, and its value is `hold.reason_detail` from the enum definitions. Only the component that owns each reason can release it. The server creates `release_ref`. An automatic release is `auto:<component>:<probe_result_id>`, an owner-attested release (`policy_activation`, `start_unknown`, `db_unavailable`) is `attested:<component>:<evidence_ref>`, and a release for a security reason is `operator:<authenticated_actor>:<console_request_id>`; operator approval is received through `operator_approval {authenticated_actor, approved_at, console_request_id}` in the release request |
| ControlHealthLease | `source_id, component, scope, scope_id, active_version?, active_bundle_revision?, loaded_artifact_digest?, canonical_version?, sensor_generation?, details?, lease_until, observed_state, reported_at`. Combines the source heartbeat and the component's active version ack into one. `details` is currently defined only for `component = netpol-collector`, and its value is `{source_epoch, file_offset, acked_through, caught_up_at?, schema_rejected_count}`. The `details` schema of other components, such as the node-sensors report of hooks, rule hash, and drop counters (TASK-09 4), is not yet defined, so `details` sent by other components are rejected until it is defined. The server stores client `details` separately from its own metadata ([TASK-10 3.7](TASK-10-correlation-health.md#37-network-policy-records-and-composite-decisions)). `component` uses only values from the [enum definitions](#enum-definitions). TASK-10 maps the caller SAN to a component through `health.component_principals`, and rejects with 403 when the component and scope in the body do not match the caller. . The node-scope lease of a component that runs one Pod per node (DaemonSet) uses `source_id = <prefix>-node/<node_uid>` (`node_uid` is the `metadata.uid` of the Node that the Pod runs on, a lowercase UUID). The prefixes are `node-sensors` → `tetragon`, `lifecycle-recorder` → `lifecycle`, `netpol-collector` → `netpol`, and `runtime-guard` → `runtime-guard`. The service SAN is the same on every node, so it is not used as `source_id`. `(source_id, component)` is the key of a lease row, so using the SAN would make it impossible to distinguish leases per node. The check that scope_id (node) must equal the node in the certificate still applies |

### Policy improvement, testing, and discovery

| Structure | Required fields/rules |
| --- | --- |
| Issue | `issue_id, tenant, source(mismatch/unknown/gap/intent_divergence/network_finding), subject_ref, reason, action_id?, gap_id?, intent_check_id?, finding_id?, evidence_ids, created_by, state(open/proposal_started/closed), created_at`. The idempotency key is the natural key `UNIQUE(source, subject_ref, reason)`. The membership basis for service session scope is `issue_evidence(issue_id, kind, ref_id)` (TASK-12), and `kind` is `issue_evidence.kind` in the [enum definitions](#enum-definitions). The basis of an issue created by the intent checker is the three rows `[intent_check_id, action_id, decision_id]`. For an issue with `source = network_finding`, `subject_ref = finding_id`, `reason` = the NetworkFinding's `kind`, and the basis is the single row `[finding_id]` (`kind = network_finding`). A NetworkFinding is workload-scoped, so the `tenant` of this issue is `*` (tenant-independent) |
| PolicyProposal | `proposal_id, issue_id?, initiated_by_actor, evidence_ids, generator_version, parent_candidate_id?, model_id, model_region, api_version, tool_declarations_digest, builder_params, candidate_digest, base_bundle_digest, patch, expected_effects, required_tests, state`. The `patch` structure and kinds are in [Appendix A](#appendix-a-policy-data-and-patch-schema). The model outputs only `builder_params`, explanations, and rationale; `patch` is produced only as typed patch JSON by the deterministic builder (Python) of TASK-12. Bundle creation and `candidate_digest` computation are handled by Go `POST /internal/policy-diff:check` (TASK-14) |
| PolicyBundle | `bundle_id, artifact_digest, candidate_digest, schema_versions, policy_revision, catalog_digest, adapter_constraints_digest, sensor_rules_digest, standing_rules_digest, rollback_compatibility, test_report_digest`. `epoch` is not included. Digest definitions are in the [policy deployment contract](#policy-deployment-contract) |
| PolicyChange | `change_id, proposal_id, created_by_actor, base_bundle_digest, candidate_bundle_digest, run_id, report_digest, fixture_set_digest, state, approval_digest?, approved_by_actor?, approval_expires_at?, target_epoch?, activation_refs, rollback_ref?, sensor_release_policies_digest, permission_widening {widened, items[] {path, added_values, removed_values}}, widening_acknowledged_items?`. `run_id` must be a run with `run_kind = candidate_final`. `approved_by_actor` must differ from both `initiated_by_actor` and `created_by_actor` |
| RegressionFixture | `fixture_id, scope, role(required/holdout/added), input, expected_by_role {baseline: Outcome, candidate: Outcome}, content_digest, governance_refs[]?`. The required set is pinned in the server's `fixture_registry(scope, required_fixture_ids, required_set_digest)`. `governance_refs[]` is the (optional) list of check item IDs from [Appendix C](#appendix-c-governance-checklist) that this fixture verifies. This field is not an input to the `content_digest` computation, so it does not change `fixture_set_digest` or `required_set_digest`. It also does not affect the fixture's judgment rules. It is not set on fixtures with `role = holdout` |
| Outcome | `{verdict, execution_state, effect(none/accepted/verified/mismatch/unknown), reason_codes[]}`. Comparison rule: it matches if the first three fields are equal and the expected `reason_codes` are a subset of the actual `reason_codes`. If the expected value is an empty array, the actual value is not examined |
| RegressionReport | `run_id, run_kind(regression/candidate_final/discovery/measurement), fixture_scope[], proposal_id?, candidate_digest, baseline_bundle_digest, fixture_set_digest, fixture_ids[], required_set_digest, required_fixture_ids[], environment_id, state, cases[] {fixture_id, expected_by_role, baseline_outcome, candidate_outcome, changed}, changed_case_count, rates[] {name, numerator, denominator, ci_method, ci_low, ci_high}, latency {p50, p95, sample_size, insufficient_sample}, decision_replay {replayed_count, changed_count, replay_inconsistent_count, excluded_batch_count, changed[] {decision_id, baseline_verdict, candidate_verdict, baseline_rule_ids, candidate_rule_ids}}, governance_summary[] {governance_id, pass, fail, not_run}, governance_map_digest, invariants, release_eligible, costs`. `governance_summary` is a reporting aggregate that counts candidate results per check item using the `governance_refs[]` of the executed fixtures (TASK-13), and it is not used to compute `release_eligible`. `governance_map_digest` is the digest of the check item mapping used by this run ([normalization and hashing](#normalization-and-hashing)). Both values are in the report, so they are inputs to `report_digest`, and the TASK-14 approval screen shows them together. `replay_inconsistent_count` is the number of inputs for which the baseline re-evaluation differs from the stored `rego_result`, and it does not stop the run. The gate applies only to candidate runs. `release_eligible` is not determined by `decision_replay` alone |
| DiscoveryCandidate | `candidate_id, library, library_version, call_site, trigger_condition, destination_template, retry_redirect_behavior, evidence_ref, model_run_ref, dynamic_match?(observed_not_static/static_not_observed/matched), matched_arms?(sorted list of off/on), reproduction_run_id?, state, promotion_kind?(allow_operation/deny_fixture/sdk_setting_check), reviewed_by_actor?, catalog_change_ref?`. `dynamic_match` is determined by the deterministic matcher |
| AlignmentResult and Mismatch | Owned and written by TASK-11. `alignment_results(action_id, revision, alignment, evidence_level, reducer_version, evaluation_time, PRIMARY KEY(action_id, revision))`, `mismatches(mismatch_id, action_id, revision, reason, severity, compared_fields, expected_digest, observed_digest, evidence_refs, affected_scope)` |

External bodies are subject to a strict schema, extra field rejection, and size/depth/string limits. For optional fields that cannot be observed, null and the reason for absence are recorded. Unknown fields outside the schema submitted by the client are rejected. Tenant, environment, and resource namespace are distinct values.

### Timeline response schema

`GET /v1/actions/{action_id}/timeline` (TASK-11) responds with the single schema below. The cursor is ordered by `(received_at, event_id)`, with at most 100 items at a time.

```json
{
  "action_id": "<uuid>", "tenant": "<tenant>",
  "verdict": "allow", "execution_state": "unknown",
  "alignment": "insufficient_evidence", "evidence_level": "unknown",
  "authorization": {"decision_basis": "standing_rule", "approval_id": null, "standing_rule_id": "<id>", "approval_revision": null, "intent_check_status": "not_run", "matched_rule_ids": []},
  "comparison": {"target": "matched", "content": "unconfirmed", "disclosure": "matched", "effect_count": null},
  "facts": [], "attempts": [], "evidence": [], "gaps": [],
  "missing_sources": ["independent_receipt"],
  "revisions": [],
  "reducer": {"reducer_version": "<v>", "evaluation_time": "<ts>",
              "correlation_algorithm_version": "<v>", "correlation_revisions": []},
  "next_cursor": null
}
```

| Item | schema |
| --- | --- |
| `comparison.*` | `target`, `content`, `disclosure`: `matched`, `mismatched`, `unconfirmed`, `not_applicable`. `effect_count`: integer or null |
| `facts[]` | `{event_id, event_type, source_id, source_time, received_at, summary, refs[]}` |
| `attempts[]` | `{attempt_id, state, reason_codes[], peer, send_started_at?, response_at?, status_code?, provider_request_id?}` |
| `evidence[]` | `{evidence_id, type(receipt/provider/kernel/audit_log/network_finding), confidence?, session_id?, source_time, received_at, ref}`. `type = network_finding` is a NetworkFinding for the same `workload_id` as this action and is a workload-scoped item. `evidence_id = finding_id`, `source_time = window_start`, `received_at` is the storage time of that revision, and `session_id` is always null. It is not execution evidence for this action or session and is not used to compute `alignment`, `evidence_level`, or `comparison` |
| `gaps[]` | `{gap_id, stage, start_at, end_at?, count_quality}` |
| `revisions[]` | `{revision, alignment, evaluation_time, reason}` |
| mismatch `reason` | `target_mismatch`, `content_mismatch`, `disclosure_mismatch`, `count_exceeded`, `duplicate_effect`, `unregistered_destination`, `unlinked_risky_kernel_event` |
| mismatch `severity` | `low`, `medium`, `high`. `high` triggers a session hold; a risk event of unknown attribution is a candidate for a workload hold |
| Risk event | The kinds of unlinked kernel events that request a workload hold: an established connect to an unregistered destination, an attempted write to a protected path, and an unexpected child process exec. The rest are only displayed. The hold has `reason = risk_event`, and the judgment conditions and `reason_detail` values for each kind are defined in [TASK-10 3.2](TASK-10-correlation-health.md#32-control-health-decision). A blocked connection attempt is not a risk event |

Replay determinism: the same event set (`received_at ≤ evaluation_time`), the same `reducer_version`, and the same correlation `algorithm_version` and revision set produce the same projection. Late evidence adds a new revision and preserves the previous judgment. Each item in `facts`, `attempts`, and `evidence` has both `source_time` and `received_at`.

## enum definitions

| enum | Values | Notes |
| --- | --- | --- |
| `verdict` | `allow`, `approval_required`, `deny` | Separate from execution and evidence states |
| `execution_state` | `denied`, `approval_pending`, `dispatch_pending`, `preflight_rejected`, `attempt_planned`, `dispatched`, `accepted`, `effect_verified`, `effect_mismatch`, `failed`, `unknown` | Derived state. Original facts are not erased. `dispatch_pending` is the period after `allow` and before an attempt is created, and it is not included in the E2E completeness denominator. Derivation rules are in [execution_state derivation](#execution_state-derivation) |
| `alignment` | `aligned`, `mismatch`, `unknown`, `insufficient_evidence`, `observation_gap` | Result of comparing the approved scope with the actual action |
| `evidence_level` | `none`, `accepted`, `effect_verified`, `effect_mismatch`, `unknown` | Target evidence level. For model/k8s calls, `accepted` is the upper bound (k8s `Audit-Id` linkage is Q0) |
| `destination_observed.missing_reason` | `MULTIPLE_EFFECTS`, `EFFECT_LIST_LIMIT_EXCEEDED`, `NO_RECEIVER_EFFECT`, `NO_RECEIVER_ATTEMPT`, `RECEIPT_UNAVAILABLE`, `NOT_RECEIVER_TARGET` | The reason the `wire_body_digest` and `bytes` observed by the receiver are null. If both have values, this is null. Handling per situation is in [TASK-08 3.2](TASK-08-destination-evidence.md#destination_observed-payload) |
| `confidence` (Correlation) | `confirmed`, `workload_inferred`, `unlinked` | |
| `request_role` (AdapterObservation) | `primary`, `pod_identity_before`, `pod_logs`, `pod_identity_after` | A single-call adapter uses `primary`. The other three are sub-requests of k8s logs ([TASK-05 3.1](TASK-05-service-adapters.md#31-actual-implementation-scope-per-adapter)) |
| `approval_kind` | `action` | For single-action user approval only |
| `revoke_reason` | `user_revoked`, `operator_revoked`, `policy_changed`, `session_ended` | |
| `session.state` | `created`, `claimed`, `expired`, `revoked` | |
| `reservation.state` | `reserved`, `committed`, `released` | `committed` is after the permit claim |
| `attempt.state` | `planned`, `claimed`, `dispatched`, `response_received`, `failed`, `unknown`, `released`, `resolved` | Covered by the active partial unique index: `planned, claimed, dispatched, unknown` |
| `start_attempt.state` | `prepared`, `issued`, `consumed`, `start_requested`, `runtime_start_returned`, `start_failed`, `start_unknown` | `start_observed` and exit are independent observation axes. The allowed transition table is in [TASK-10 3.5](TASK-10-correlation-health.md#35-startup-state-identity-and-retry-implementation) |
| `startup_capture` | `guarded`, `unsupported` | `unsupported` is an observation and gap-reporting mode |
| `hold.scope` | `global`, `node`, `workload`, `target`, `session` | |
| `hold.reason` | Transient failures: `export_lag`, `db_unavailable`, `probe_failed`, `lease_expired`, `start_unknown`, `sensor_degraded` (owner `node-sensors`, release condition: drop counter unchanged for 120 seconds + 2 consecutive probe passes). Security: `control_drift`, `bypass_detected`, `sensor_tampering`, `alignment_mismatch`, `audit_integrity` (a global hold requested by the TASK-07 verifier when it finds a mismatch in the manifest chain, export objects, or outbox ack), `risk_event` (a workload hold for a risk event; decision rules and owner are in [TASK-10 3.2](TASK-10-correlation-health.md#32-control-health-decision)). Policy: `policy_activation`. Operator: `operator_stop` (a stop placed directly by an operator from the console; its creation effects are in [Operator stop](#operator-stop)) | Transient failures are released automatically by the owning component after the probe passes (audit event). However, `start_unknown` and `db_unavailable` are released after owner confirmation. Security reasons and `operator_stop` are released only with operator approval. `policy_activation` is released by TASK-14 |
| health status | `healthy`, `degraded`, `unhealthy` | External export delay is `degraded` (not a hold); when the lag limit is exceeded, an `export_lag` hold is placed |
| `count_quality` | `exact`, `estimated`, `unknown` | |
| `issue.source` | `mismatch`, `unknown`, `gap`, `intent_divergence`, `network_finding` | `network_finding` is created by TASK-10 ([TASK-10 3.7](TASK-10-correlation-health.md#37-network-policy-records-and-composite-decisions)) |
| `issue_evidence.kind` | `action`, `decision`, `run`, `bundle`, `gap`, `intent_check`, `network_finding` | This table is the only definition. The evidence API returns only IDs that have this row. No evidence operation reads `network_finding` |
| `intent_check_status` | `completed`, `not_run` | If `not_run`, the deterministic decision is kept |
| `intent_check.overall` | `consistent`, `divergent`, `unclear` | `consistent` does not add permissions |
| `discovery_candidate.state` | `candidate`, `reproduced`, `promoted`, `rejected` | `promoted` only after dynamic reproduction + human review |
| `run_kind` | `regression`, `candidate_final`, `discovery`, `measurement` | Only `candidate_final` includes the holdout and can be an input to `POST /v1/policy-changes` |
| `data_class` | `none`, `synthetic`, `internal`, `confidential` | Ranks 0 to 3 in this order. The high-water mark never decreases |
| `verified_session.kind` | `user`, `service` | OPA input |
| `record_kind` (`audit_outbox`) | `audit_event`, `kernel_event`, `lifecycle_event`, `decision_input` | The source table of the outbox row. The destination for `decision_input` is `gcs_decision_inputs` |
| `decision_basis` | `approval`, `standing_rule`, `service_scope`, `activation_probe` | Required when `allow`, otherwise null |
| `decision_stage` | `normalize`, `opa` | `normalize` is a denial before OPA evaluation (rule_id prefix `normalize.`) |
| `fixture_scope` | `core`, `intent`, `discovery`, `startup_gate`, `measurement` | `work-readiness-*` and `session-worker-*` are in the required `core` set. An optional file-isolation profile makes additional fixtures required. Only `startup_gate` is not required for release |
| User roles | `operator`, `approver`, `release_operator`, `viewer` | Mapped to IdP groups. Installation input is TASK-03 |
| `POST /internal/holds` decision | `created`, `existing`, `rejected` | |
| `model_profile` | `agent`, `policy_proposal`, `intent_check`, `discovery` | Limits are in TASK-05 |
| `baseline_kind` | `admission`, `exec_rbac`, `network_policy`, `node_pool_config`, `sensor_policy` | Target resources and digest rules are in TASK-01; periodic comparison is the TASK-10 drift probe |
| `WorkReadinessCheck.reason_codes` | `POD_OBSERVATION_NOT_READY`, `WORKER_OBSERVATION_NOT_READY`, `WORKER_BINDING_MISMATCH`, `WORKER_EXITED`, `WORKER_ISOLATION_NOT_READY`, `WORK_READINESS_EXPIRED`, `WORK_READINESS_BINDING_MISMATCH`, the existing `CONTROL_HEALTH_UNAVAILABLE`, `HOLD_ACTIVE`, session and budget denial codes | Readiness failure/expiry is 503; a different identity/session binding is 403. Unsupported or missing states are not presumed to be ready |
| `SessionProcessBinding.state` | `pending`, `observed`, `closed`, `invalidated` | Reassignment and state restoration are prohibited. A subsequent worker gets a new worker_instance_id/binding_id |
| `SessionProcessBinding.reason_codes` | `WORKER_OBSERVATION_NOT_READY`, `WORKER_BINDING_MISMATCH`, `WORKER_EXITED`, `WORKER_ISOLATION_NOT_READY`, `WORKER_REGISTRATION_CONFLICT` | Identity mismatch is 403; different content under the same ID or concurrent registration is 409; not ready or unknown observation is 503/blocked. A simple timeout keeps pending or triggers a new readiness check, and automatic re-execution of work is prohibited |
| `KernelSessionAttribution.status` | `linked`, `unlinked` | Decides only the basis for process session ownership. Separate from confirming action/attempt execution |
| `hold.reason_detail` | `unregistered_connect_established`, `protected_path_write`, `unexpected_child_exec` | Used only when `reason = risk_event`. Corresponds one-to-one with the three kinds of risk events in the timeline schema below |
| `LifecycleRecord.missing_reason` | `not_resolved_by_watcher`, `runtime_metadata_partial` | The reason an optional field is empty. `not_resolved_by_watcher`: the pod-watcher mapping (version 1) did not fill `node_uid`, `boot_id`, or the container fields without a verified resolver (TASK-09 3.6). `runtime_metadata_partial`: the runtime recorder failed to fill one or more optional runtime fields (`cgroup_inode`, `image_id`, `image_manifest_digest`, `restart_instance`, and so on). A new reason is used only after it is added to this table |
| `KernelEvent.metadata_status` | `resolved`, `tuple_scoped`, `unresolved` | The source of the Pod metadata determined by the exporter ([TASK-09 4](TASK-09-node-sensor.md#4-api-data-and-linkage-contract-ref)). `resolved`: in the read-only Pod API, the container matched exactly one observed Pod, and `container_id` and `pod_uid` were filled. `tuple_scoped`: the softirq `tcp_state` was scoped only by the observed Pod IP in the tuple, and the process and Pod fields are null. `unresolved`: an event whose attribution could not be confirmed but that was kept rather than discarded; `container_id` and `pod_uid` are null |
| `KernelEvent.coverage` | `complete`, `partial` | `complete` if all identity fields that the event_type can have were observed; `partial` if any is null (field table in TASK-09 4). `partial` events are stored but are not used for identity decisions such as the worker gate (TASK-07) |
| `ObservationGap.stage` | `kernel_sensor_export`, `lifecycle_capture`, `network_policy_log` | The collection stage where the gap occurred. This table is the only definition, and the CHECK on `health.observation_gaps` enforces it (TASK-10 3.6) |
| `ObservationGap.reason` | `kernel_sensor_export`: `SEQUENCE_RANGE_ABANDONED`, `EXPORT_ROTATION_LOSS`, `NODE_LOST_BEFORE_ACK`. `lifecycle_capture`: `SEQUENCE_RANGE_ABANDONED`, `WATCH_HISTORY_EXPIRED`, `RUNTIME_RECORD_MISSING`, `METADATA_UNRESOLVED`, `NODE_LOST_BEFORE_ACK`. `network_policy_log`: `SEQUENCE_RANGE_ABANDONED`, `NETPOL_COLLECTOR_STOPPED`, `NETPOL_FILE_ROTATION_LOSS`, `NETPOL_NODE_LOG_DROPPED`, `NODE_LOST_BEFORE_ACK` | The gap reason, which is separate from `reason_codes` in API responses. Only the values listed for each stage are allowed. `NETPOL_COLLECTOR_STOPPED` is a collection delay caused by a stopped node collector, `NETPOL_FILE_ROTATION_LOSS` is the interval erased by rotation in the meantime, and `NETPOL_NODE_LOG_DROPPED` is logs the node discarded after exceeding the limit |
| `ObservationGap.recovery_state` | `open`, `backfilled`, `partially_recovered`, `unrecoverable` | `open`: in progress or recovery not yet determined. `backfilled`: the interval was fully re-read from the remaining source (not a proof of no loss). `partially_recovered`: only part was re-read. `unrecoverable`: cannot be re-read because the source is gone. Closed gaps are not erased either |
| `NetworkPolicyRecord.disposition` | `allow`, `deny` | Log value as is |
| `NetworkPolicyRecord.direction` | `ingress`, `egress` | Log value as is |
| `NetworkPolicyRecord.protocol` | `tcp`, `udp`, `icmp` | Log value as is |
| `network_segment` | `exec_to_control`, `exec_to_exec`, `exec_to_cluster_api`, `exec_to_metadata`, `exec_to_internal_other`, `exec_direct_external`, `control_to_control`, `control_to_target`, `control_to_google_api`, `control_to_external`, `unclassified` | Derived deterministically from the role of the source Namespace and the classification of the destination address. Classification rules are in TASK-10 3.7. `unclassified` if it cannot be classified |
| `boundary_crossing` | `internal`, `external`, `unknown` | Whether the destination is an address inside the cluster or VPC. `unknown` if it cannot be classified |
| `NetworkFinding.kind` | `blocked_attempt`, `unregistered_established`, `unmatched_attempt`, `unmatched_deny` | Decision rules are in TASK-10 3.7 |
| `NetworkFinding.outcome` | `blocked`, `established`, `unknown` | `unknown` means it is not concluded to be either a violation or a non-occurrence |
| `ControlHealthLease.component` | `gateway`, `coordinator` (including the sweeper), `adapter` (distinguished by `source_id` per Deployment), `audit-db`, `audit-export`, `destination-evidence`, `node-sensors` (sensor and exporter), `lifecycle-recorder`, `runtime-guard` (`guarded` nodes only), `start-coordinator` (required only for `guarded` combinations), `node-readiness`, `releaser`, `netpol-collector` (the node collector for network policy logs; node scope, not included in the required lease set) | Scope rules are in TASK-10. Because `netpol-collector` is a collector of supplementary evidence, expiry or `degraded` of this lease does not create a hold. Components that load bundles (gateway, adapter) report the loaded bundle's `artifact_digest` in `loaded_artifact_digest` and the OPA revision in `active_bundle_revision`. Other components report their active version in `active_version`. Ack completion is "the number of valid leases whose `loaded_artifact_digest` equals the desired digest = Deployment `status.replicas`" |
| Proposal states | `draft → validated`, `draft → rejected`, `draft → invalid`, `validated → stale` | `invalid`: output schema violation, `MAX_TOKENS`, or budget exceeded. `rejected`: the schema is valid, but verification of the patch scope, evidence permissions, or base bundle was rejected. `stale`: `base_bundle_digest` is no longer the active bundle |
| report states | `pass`, `fail`, `incomplete`, `not_run`, `invalid_environment`, `unsupported` | `release_eligible` can be true only when `pass` |

**Policy change state transitions:**

| Current | Next | Condition and actor |
| --- | --- | --- |
| (proposal `validated`) | `proposed` | Operator `POST /v1/policy-changes` (TASK-14). The `run_id` of a `run_kind = candidate_final` run that includes the holdout is required |
| `proposed` | `tested` / `test_failed` | The releaser confirms that the run's report has `pass`, `release_eligible`, and a matching candidate digest, and stores `permission_widening` |
| `tested` | `approved` | `.../approve` by an approver different from the proposer. If `widened = true`, acknowledgement per widening item is required. The approval is bound together with the rollback conditions and the rollback target bundle (`base_bundle_digest`) |
| `approved` | `staged` / `approval_expired` | The release operator must call `POST /v1/policy-changes/{change_id}/activate` within 30 minutes of approval to move to `staged`. In this step the signed bundle is uploaded to GCS and first loaded into the regression test environment with the same releaser procedure. If it is not started within 30 minutes, the state is `approval_expired` and approval must be obtained again |
| `staged` | `activating` | Activation order of the [policy deployment contract](#policy-deployment-contract): create hold → update `desired_bundle` → lease ack from all expected replicas (120 seconds) → `active_policy` epoch CAS |
| `activating` | `verified` / `failed` | Release the hold if the activation probe passes, `failed` if it fails |
| `failed`, `verified` | `rolled_back` | `.../rollback` (release operator) activates a new epoch with the previous bundle that was bound at approval time. It is performed without separate approval, and as a result the allowed scope may widen back to the previous level |

## reason code dictionary

Responses, audits, and decisions put only the values below into `reason_codes`.

| reason code | HTTP | Origin (owner) | Meaning |
| --- | --- | --- | --- |
| `AUTH_REQUIRED` | 401 | Common | No authentication or expired authentication |
| `HOLD_REQUEST_DENIED` | 403 | TASK-10 | Verification failed for the authenticated hold requester's component registration, reason/scope permission, or the certificate's node/boot binding. Used for `decision = rejected` of `POST /internal/holds` |
| `CLAIM_CODE_INVALID` | 403 | TASK-03 | claim_code mismatch, expiry, or reuse |
| `SESSION_BINDING_INVALID` | 403 | TASK-04 | actor/session/workload binding mismatch |
| `ENDPOINT_NOT_REGISTERED` | 403 | TASK-02 normalization, TASK-04 Rego | Service, operation, or target not in the catalog. `unknown_operation` in the plan. Unregistered `operation_id` and `target_id` are rejected with this code at the normalization stage, and because no envelope can be built, `request_rejected` is recorded without an action or decision. Argument schema violations of a registered operation are `SCHEMA_INVALID` |
| `SERVICE_SCOPE_DENIED` | 403 | TASK-04 Rego | A service session request is outside the profile's allowed operations and targets |
| `TARGET_SCOPE_DENIED` | 403 | TASK-04 | Outside the destination, namespace, tenant, or environment scope |
| `DISCLOSURE_SCOPE_DENIED` | 403 | TASK-04 | Outside the allowed disclosure fields |
| `CONTENT_PATTERN_DENIED` | 403 | TASK-02 normalization, TASK-04 decision | Rejected by a deterministic content checker (synthetic email patterns, etc.). Not a general-purpose DLP |
| `DATA_CLASS_DENIED` | 403 | TASK-04 | The high-water mark exceeds the target's allowed class |
| `APPROVAL_REQUIRED` | 202 | TASK-04 | `approval_required` decision |
| `INTENT_DIVERGENCE_ESCALATED` | 202 | TASK-04 | A standing rule allow candidate was escalated by intent check `divergent` |
| `INTENT_ACK_REQUIRED` | 422 | TASK-03 | Missing acknowledgement of a divergent/unclear finding |
| `PERMISSION_WIDENING_ACK_REQUIRED` | 422 | TASK-14 | An attempt to approve a change with `permission_widening.widened = true` without acknowledgement per widening item |
| `LOCK_TIMEOUT` | 503 | TASK-03 (reservation, permit), TASK-14 (activation) | Row lock timeout (2 seconds) exceeded |
| `APPROVAL_INVALID` | 403 | TASK-04 | Mismatch between the approval contract and the envelope |
| `APPROVAL_UNAVAILABLE` | 409 | TASK-03 (reservation), TASK-04 (decision) | Expired, canceled, or budget exhausted |
| `SESSION_BUDGET_EXHAUSTED` | 409 | TASK-03 | Standing rule session budget exhausted |
| `CONTEXT_INCOMPLETE` | 403 | TASK-04 Rego | A required OPA input key is missing |
| `POLICY_UNAVAILABLE` | 503 | TASK-04 | OPA non-200, no result, or schema error |
| `POLICY_VERSION_MISMATCH` | 503 | TASK-04 | The bundle revision that the embedded OPA used for evaluation differs from the expected active revision |
| `POLICY_EPOCH_STALE` | 409 | TASK-03 | Decision epoch ≠ active epoch at reservation. `:reevaluate` required |
| `CATALOG_DIGEST_MISMATCH` | 409 | TASK-03/04/05 | The catalog_digest of the decision or envelope differs from the active value |
| `DECISION_EXPIRED` | 409 | TASK-03 | Decision TTL elapsed |
| `HOLD_ACTIVE` | 503 | TASK-03 (reservation), TASK-04 (decision) | Unreleased hold on the relevant scope |
| `CONTROL_HEALTH_UNAVAILABLE` | 503 | TASK-03/04/10 | Required lease expired or cannot be queried |
| `POD_OBSERVATION_NOT_READY` | 503 | TASK-09/10 decision, TASK-04 delivery | The Pod's mapping/filter/WAL/nonce evidence is not ready, or challenge timeout |
| `WORK_READINESS_EXPIRED` | 503 | TASK-04/10/15 | The confirmation expired, or the current value of generation/policy/binding changed. A new confirmation is required |
| `WORK_READINESS_BINDING_MISMATCH` | 403 | TASK-04/10 | Reuse of a confirmation or nonce belonging to a different caller/session/work_run_id |
| `CLIENT_KEY_BODY_CONFLICT` | 409 | TASK-04 | Different body for the same client_request_key |
| `PREFLIGHT_MISMATCH` | 409 | TASK-05 | Mismatch between the WirePlan and the contract or decision |
| `CONTENT_DIGEST_MISMATCH` | 409 | TASK-05 | Original digest mismatch in `action_contents` |
| `DESTINATION_NOT_ALLOWED` | 403 | TASK-05 | The connection IP is outside the target CIDR allowlist |
| `TLS_VERIFY_FAILED` | 502 | TASK-05 | Certificate or SNI verification failed |
| `CREDENTIAL_UNAVAILABLE` | 503 | TASK-03, TASK-06 | Broker rejection or lookup failure, or certificate issuance failure by the identity CA (CAS) (`POST /internal/workload-certificates` 503) |
| `PERMIT_INVALID` | 409 | TASK-03 | Permit expired, canceled, or already claimed |
| `RESPONSE_TOO_LARGE` | 502 | TASK-05 | Response byte limit exceeded |
| `TARGET_REJECTED` | 502 | TASK-05 | The target rejected the request (3xx, target-specific 4xx). Attempt `failed` |
| `TARGET_UNAVAILABLE` | 503 | TASK-05 | Target overload or outage (429, 5xx). A receiver 5xx is attempt `unknown` |
| `MODEL_BLOCKED` | 502 | TASK-05 | The model blocked the response due to safety policy or similar (a blocking value of `finishReason`, `promptFeedback.blockReason`) |
| `TARGET_IDENTITY_CHANGED` | 409 | TASK-05 | Pod UID re-query mismatch after a k8s logs response. The result is discarded, alignment `mismatch` |
| `TARGET_IDENTITY_UNCONFIRMED` | 502 | TASK-05 | After k8s logs were received, the Pod UID re-query did not end with a 200 response. The received logs are discarded from the result. If there is no response after `WroteHeaders` of the re-query, attempt `unknown` and `execution_state = unknown`. If the re-query failed before `WroteHeaders` or received a complete non-200 response, attempt `response_received` and `execution_state = failed` ([TASK-05 3.3](TASK-05-service-adapters.md#33-actual-invocation-sequence-and-state-mapping)) |
| `EVENT_ID_CONFLICT` | 409 | TASK-07 | Same event_id, different digest |
| `TARGET_KEY_BODY_CONFLICT` | 409 | TASK-08 | Same action_key, different body |
| `RECEIVER_KEY_INVALID` | 401 | TASK-08 | The `X-Agentarium-Receiver-Key` of a receiver submission is missing or differs from the active key. Rejected before any DB write, and no receive attempt is recorded |
| `TOOL_NOT_REGISTERED` | 403 | TASK-12 | The model requested an unregistered tool |
| `TOOL_BUDGET_EXHAUSTED` | 409 | TASK-03/12 | Service session tool budget exhausted |
| `SERVICE_SESSION_ACTIVE` | 409 | TASK-03 | No new session is issued because the same candidate (`issue_id`, `candidate_id`) still has an active service session |
| `MODEL_OUTPUT_TRUNCATED` | 502 | TASK-05/12 | `finishReason = MAX_TOKENS` |
| `MODEL_SCHEMA_INVALID` | 422 | TASK-12 | Structured output re-validation failed |
| `STARTUP_GUARD_UNAVAILABLE` | 503 | TASK-09/10 | Non-fatal rejection because the guard check is unavailable or the deadline is imminent |
| `SCHEMA_INVALID` | 422 | Common | Violation of schema, duplicate keys (including keys differing only in case), NaN, range, or invalid UTF-8 |
| `ACTION_DIGEST_MISMATCH` | 409 | TASK-04 | The expected action_digest of `:reevaluate` differs from the stored value |
| `RESOURCE_NOT_FOUND` | 404 | Common | Resource that does not exist or is outside the caller's scope (hides whether it exists in another tenant) |
| `STATE_STORE_UNAVAILABLE` | 503 | Common | DB read, write, or fact lookup failure |
| `OUTCOME_TIMEOUT` | Not applicable (internal) | TASK-03 sweeper | No outcome report within 60 seconds after claim. Attempt `unknown` |
| `BODY_TOO_LARGE` | 413 | Common | |
| `RATE_LIMITED` | 429 | Common | Includes `Retry-After` |
## event_type registry

`POST /internal/audit/events` and the batch API accept only the `event_type` values below. The first 26 are the required events from plan chapter 7, and the rest are events added in this revision. "Expected state" is the `execution_state` for which the E2E evidence completeness calculation requires that event.

| event_type | producer | Required payload fields | Expected state |
| --- | --- | --- | --- |
| `contract_created` | TASK-03 | action_id, contract_digest, displayed_contract_digest, contract_version | All states from approval_pending onward on the approval path |
| `approval_requested` | TASK-04 | action_id, decision_id, reason_codes | All of the approval path |
| `approval_granted` | TASK-03 | approval_id, revision, action_id, displayed_contract_digest, policy_epoch, acknowledged_findings | All states from preflight_rejected onward on the approval path |
| `approval_revoked` | TASK-03 | approval_id, revoke_reason, policy_epoch? | When a revocation occurred |
| `request_received` | TASK-04 | action_id, request_id, session_id, operation_id, client_request_key_digest | All states |
| `policy_decided` | TASK-04 | decision_id, decision_stage, verdict, reason_codes, decision_basis?, matched_rule_ids, evaluated_rule_ids, gateway_added_rule_ids, policy_bundle_id, policy_epoch, opa_bundle_revision?, catalog_digest, approval_id?/standing_rule_id?/service_session_id?/activation_probe_id? | All states |
| `preflight_passed` | TASK-05 | action_id, decision_id, wire_body_digest, catalog_digest | All states from attempt_planned onward |
| `preflight_rejected` | TASK-05 | action_id, decision_id, reason_codes, compared_fields | preflight_rejected |
| `attempt_planned` | TASK-03 | attempt_id, reservation_id, action_digest, policy_epoch | All states from attempt_planned onward |
| `dispatch_started` | TASK-05 | attempt_id, request_ordinal, request_role, peer_addr, peer_port, send_started_at | All states from dispatched onward (excluding failed cases that failed before claim) |
| `response_received` | TASK-05 | attempt_id, request_ordinal, request_role, status_code, provider_request_id?, k8s_audit_id?, response_at | accepted, effect_verified, effect_mismatch |
| `attempt_uncertain` | TASK-05, TASK-03 sweeper (`OUTCOME_TIMEOUT`) | attempt_id, stage, reason_codes | unknown |
| `destination_observed` | TASK-08 | action_id, action_key?, rule_id, evidence_level, receipt_digest?, effect_count?, wire_body_digest? (body SHA-256 computed by the receiver), bytes?, effects?[] {wire_body_digest, body_bytes}, missing_reason?. wire_body_digest and bytes are filled only when there is exactly one effect, and if they are null, missing_reason is required. They are not filled with adapter values, 0, the first effect, or a synthetic digest. Null combinations and limits are in [TASK-08 3.2](TASK-08-destination-evidence.md#destination_observed-payload) | One per collector decision R1–R6: receiver.submit effect_verified (R1), effect_mismatch (R2, R3), unknown (R5), failed after attempt_failed (R6), accepted for k8s and model calls (R4) |
| `alignment_checked` | TASK-11 | action_id, alignment, evidence_level, reducer_version, compared_fields | All states (for denied, the scope of confirming non-execution) |
| `execution_held` | TASK-10 | hold_id, scope, scope_id, reason, owner_component | effect_mismatch, when rejected by a hold |
| `source_health_changed` | TASK-10 | source_id, scope, from_state, to_state, lease_until | When applicable |
| `evidence_gap_detected` | TASK-10 | gap_id, stage, affected_scope | All states within the affected scope |
| `evidence_gap_resolved` | TASK-10 | gap_id, recovery_state, evidence_refs | When applicable (past gaps are kept) |
| `kernel_event_observed` | TASK-09 (received by TASK-07) | source_event_id, source_epoch, source_sequence, event_type, record_digest. process_exec_id is required for process context events other than tcp_state. tcp_state requires tcp_new_state | Kernel test cases |
| `kernel_correlation_checked` | TASK-10 | correlation_id, kernel_event_id, confidence, algorithm_version, revision | Kernel test cases |
| `network_finding_recorded` | TASK-10 | finding_id, revision, kind, outcome, network_segment, boundary_crossing, confidence, workload_id?, rule_version, algorithm_version | Network decision test cases. One per NetworkFinding revision, and tenant is `*` |
| `control_drift_detected` | TASK-10 | baseline_kind, expected_digest, observed_digest, scope | When applicable |
| `policy_proposed` | TASK-12 | proposal_id, issue_id, candidate_digest, base_bundle_digest, state | Policy improvement flow |
| `policy_tested` | TASK-13 | run_id, run_kind, candidate_digest, baseline_bundle_digest, fixture_set_digest, report_digest, state, release_eligible | Policy improvement flow |
| `policy_change_approved` | TASK-14 | change_id, approval_digest, approved_by_actor, widening_acknowledged_items, expires_at | Policy improvement flow |
| `policy_deployed` | TASK-14 | change_id, bundle_id, artifact_digest, target_components | Policy improvement flow |
| `policy_activation_verified` | TASK-14 | change_id, policy_epoch, component_acks | Policy improvement flow |
| `policy_reverified` | TASK-14 | change_id, probe_action_ids, outcome | Policy improvement flow |
| `policy_rolled_back` | TASK-14 | change_id, from_epoch, to_epoch, reason | Rollback test |
| `session_created` | TASK-03 | session_id, workload_id, task_statement_digest, claim_expires_at | Precondition fact for all states |
| `session_claimed` | TASK-03 | session_id, workload_identity | A fact of token assignment, not evidence that work started |
| `work_readiness_requested`, `work_readiness_passed`, `work_readiness_blocked` | TASK-10 | check_id, work_run_id, checkpoint, session_id, workload_id, worker_instance_id, worker_binding_id, root_exec_id?, instance_binding, sensor_generation, policy_epoch, reason_codes, evidence_refs, checked_at?, expires_at? | Every work start, resume, and model/tool control point |
| `session_worker_registered`, `session_worker_observed`, `session_worker_closed`, `session_worker_invalidated` | TASK-10 (registration input from TASK-15, independent observation from TASK-09) | worker_binding_id, worker_instance_id, session_id, runtime_process_epoch, root_exec_id?, state, evidence_refs, reason_codes | Stored via the decision transaction/outbox. observed alone does not claim that user work started |
| `agent_work_start_requested`, `agent_work_started`, `agent_work_paused`, `agent_work_finished` | TASK-15 (trusted runner report, received by TASK-07) | work_run_id, session_id, check_id, runtime_process_epoch, worker_instance_id, worker_binding_id, outcome?, reason? | An application report, not independent evidence of kernel observation or external effects |
| `service_session_created` | TASK-03 | service_session_id, caller_principal, issue_id?, change_id?, tool_budget | Service caller flow |
| `action_reevaluated` | TASK-04 | action_id, previous_decision_id, decision_id, policy_epoch | When re-decided |
| `intent_checked` | TASK-04 | intent_check_id, action_id, model_id, prompt_template_digest, contract_digest, findings_digest, intent_check_status | Actions subject to intent check |
| `attempt_failed` | TASK-05 | attempt_id, stage (connect/tls/write_headers), reason_codes | failed that failed after claim and before `WroteHeaders` |
| `attempt_released` | TASK-03 | attempt_id, reservation_id, reason_codes, budget_restored, released_by (adapter/sweeper) | failed that failed before claim |
| `unknown_resolved` | TASK-11 | action_id, attempt_id, resolution, evidence_refs, resolved_by_actor | Resolved unknown |
| `observation_gap_recorded` | TASK-07 (abandoned ranges), TASK-10 (otherwise) | gap_id, stage, reason, sequence_range? {from_seq,to_seq}, count_quality | Gap test cases |
| `sequence_range_abandoned` | TASK-07 (on receiving a validated TASK-09 declaration) | source_id, stream, source_epoch, range {from_seq,to_seq}, reason, range_digest | Gap test cases |
| `export_verification_failed` | TASK-07 (`audit-verifier`) | chain_id, manifest_seq, failure_code, object_key? | On verification failure. `failure_code` uses only the values in [TASK-07 3.2.1](TASK-07-audit-store.md#321-confirmed-export-items) |
| `hold_requested` | TASK-10 control-health (requesters TASK-07/09/11/14 etc.; for operator_stop, the receiver that validated the console BFF) | scope, scope_id, reason, requester, evidence_refs, authenticated_actor?, console_request_id?, justification? | Recorded as a control-health audit source for every request that passed the permission check, and requester is the validated caller SAN. It is stored atomically with a new hold and execution_held, and a response for an existing hold is also returned after the hold_requested COMMIT. The requester does not create the same event separately. The operator fields of operator_stop are validated according to the operator stop contract below |
| `hold_released` | TASK-10 (owning component or operator approval) | hold_id, release_ref, released_by, justification | When applicable |
| `issue_created` | TASK-12 | issue_id, source, action_id?, gap_id?, intent_check_id?, finding_id? | Policy improvement flow |
| `activation_probe_registered` | TASK-03 (caller TASK-14) | activation_probe_id, change_id, service_session_id, client_request_key, target_epoch | Policy improvement flow |
| `start_permit_issued`, `start_permit_consumed`, `start_requested`, `runtime_start_returned`, `start_observed`, `start_failed`, `start_unknown` | TASK-10 (start coordinator); `start_observed` is confirmed by TASK-10 with sensor evidence | start_attempt_id, binding_digest, per-transition event ref | Start cases on nodes where `startup_guard_gate` is active |
| `start_guard_bypass_detected` | TASK-10 | container_id, pod_uid, exec_event_ref, reason | When an exec is observed without a consumed permit |
| `discovery_candidate_recorded` | TASK-02 | candidate_id, library, library_version, call_site, model_run_ref | Discovery run |
| `discovery_candidate_promoted` | TASK-02 | candidate_id, promotion_kind, reviewed_by_actor, catalog_change_ref? | Discovery promotion |
| `decision_replayed` | TASK-13 | run_id, baseline_bundle_digest, candidate_digest, replayed_count, changed_count, replay_digest | Policy improvement flow |
| `permission_widening_checked` | TASK-14 | change_id, candidate_digest, widened, items_digest | Policy improvement flow |
| `lifecycle_recorded` | TASK-09 (received by TASK-07) | lifecycle_event_id, source_epoch, source_sequence, pod_uid, transition, record_digest | Short-lived Pod and lifecycle test cases |
| `request_rejected` | TASK-04 | request_id, session_id?, operation_id?, reason_codes, raw_body_digest? | Rejection before the envelope is built (excluding authentication failure; `SCHEMA_INVALID` etc.). No action row is created |
| `policy_evaluation_failed` | TASK-04 | request_id, action_id?, reason_codes (`POLICY_UNAVAILABLE`/`POLICY_VERSION_MISMATCH`), loaded_revision?, expected_revision | OPA evaluation not possible. No decision row is created |
| `policy_bundle_loaded`, `policy_bundle_load_failed` | TASK-04, TASK-05 | component, source_id, artifact_digest, revision?, reason? | Bundle load result |
| `dispatch_enqueued` | TASK-04 | decision_id, adapter_id (`execute_requests` row created) | Durably stores the execute handoff in the same transaction as the allow decision |
| `session_revoked`, `session_refreshed` | TASK-03 | session_id, authenticated_actor, expires_at? | When applicable |
| `intent_check_requested` | TASK-04 | action_id, path (approval_contract/standing_rule) | Actions subject to intent check |

**Minimum expected events per state** (denominator basis for E2E evidence completeness; computed by TASK-13 `packages/evaluation`):

| execution_state | Minimum expected events |
| --- | --- |
| `denied` | request_received, policy_decided, alignment_checked |
| `approval_pending` | request_received, policy_decided, approval_requested, contract_created |
| `dispatch_pending` | Excluded from the denominator (transient state) |
| `preflight_rejected` | The decision events above + (approval_granted on the approval path) + preflight_rejected |
| `attempt_planned` | Decision events + preflight_passed + attempt_planned |
| `dispatched` | Up to attempt_planned + dispatch_started |
| `accepted` | Up to dispatched + response_received + alignment_checked. For k8s and model calls, destination_observed (R4) is also required |
| `effect_verified` | Up to accepted + destination_observed |
| `effect_mismatch` | Up to accepted + destination_observed + execution_held |
| `failed` | Up to attempt_planned + attempt_released or attempt_failed. For attempt_failed on receiver.submit, destination_observed (R6) is also required |
| `unknown` | Up to attempt_planned + attempt_uncertain, or no response after dispatch_started. For receiver.submit, destination_observed (R5) after the observation deadline is also required |

The approval path additionally requires `session_created`, `session_claimed`, `contract_created`, and `approval_granted`, and the standing rule path additionally requires a `policy_decided` that has a `standing_rule_id`.

## Normalization and Hashing

- Business-semantic normalization → allowed JSON → JCS (RFC 8785) → UTF-8 → SHA-256. This sequence is called the "canonical digest". The Go JCS candidate is the Go implementation in `github.com/cyberphone/json-canonicalization`. The owner (TASK-02) checks the repository, license, and version, and finalizes it after it passes `vectors.json`, which contains the RFC test vectors and cases with characters outside the BMP and decimal numbers.
- Only the shared Go package `packages/canonical/` computes normalization, JCS, and hashes, and the gateway and adapters use the same package. This package also owns the test vectors `testdata/vectors.json` and `testdata/observation_vectors.json` and the UUIDv5 namespace constants. Python components do not compute digests; they use gateway API results or the output of the Go CLI `canonical-digest`.
- **Go strict JSON:** v1 `encoding/json` accepts objects with duplicate names ([encoding/json](https://pkg.go.dev/encoding/json)) and maps struct fields case-insensitively. Therefore the input is first scanned with `json.Decoder.Token()` and all of the following are rejected; then it is decoded with a new Decoder with `DisallowUnknownFields()` and `UseNumber()` enabled.
  - Duplicates of the same key or of keys that differ only in case
  - Keys that do not exactly match a struct tag (including case differences)
  - Invalid UTF-8 and unpaired surrogates (a lone `\uD800`–`\uDFFF`)
  - Depth over 16 (the top-level object is 1), keys over 128 bytes, values outside the integer range, and non-standard values such as NaN and Infinity
  - Each of these four types is included in `vectors.json` as a rejection case. Python services (FastAPI) use Pydantic strict mode and reject extra fields.
- Fields with set semantics are deduplicated and sorted by their JCS-serialized byte order. Arrays whose order is meaningful are kept as is. JCS itself is not assumed to normalize Unicode semantics. Optional fields are not omitted; they are included as `null`.
- Disclosure control is per field. A deterministic content checker in the normalization stage is applied to receiver `summary`, and violations are rejected with `CONTENT_PATTERN_DENIED`. This is not general-purpose DLP.
- User raw URLs are not allowed. Hosts and routes are registered values. TASK-02 fixes the conventions for host lowercase/IDNA, resource casing, and slash handling as per-service values.
- Secrets and Authorization are excluded from general audit and from hash input. A simple hash of a sensitive value is not anonymization. Only synthetic or non-sensitive digests go directly into the audit; sensitive references are separated into an authorized store.

| digest | Computation | Owner |
| --- | --- | --- |
| `action_digest` | canonical digest(`{operation_id, canonical_target, disclosure_fields, content_digest, limits, catalog_digest, canonicalization_version, schema_version, environment, tenant}`). Only these 10 keys are used. `data_class`, `data_sources`, `bytes`, request/attempt IDs, trace, and timestamps are not included | TASK-02 |
| `raw_body_digest` | SHA-256 of the raw body bytes of the client request. Resubmissions with the same `client_request_key` are compared with this value (if different, `CLIENT_KEY_BODY_CONFLICT`) | TASK-04 |
| `content_digest` | Canonical digest of the semantic content subject to approval. The table of included fields per operation belongs to TASK-02 (logs: pod and container in `canonical_target`, tailLines and limitBytes in `limits` / list: limit as a fixed constant / model: generation config, tool declaration, and output schema digest / receiver: payload JCS digest) | TASK-02 |
| `wire_body_digest` | SHA-256 of the body bytes actually sent. The receiver body is the JCS-serialized payload and is compared with the value computed by the receiver | TASK-05, 08 |
| `catalog_digest` | SHA-256(JCS(`{"operations": [sorted by operation_id], "targets": [sorted by target_id]}`)). YAML is strictly decoded and converted to JSON before computation. `catalog_version` is a display label | TASK-02 |
| `contract_digest` | canonical digest(ContractView JSON) | TASK-03 |
| `fixture_set_digest` | canonical digest(list of `{fixture_id, content_digest, role}` sorted by `fixture_id`). The runner computes and returns it. A fixture's `governance_refs[]` is not an input to `content_digest`, so it is not included in this value | TASK-13 |
| `governance_map_digest` | canonical digest(`{ids_digest, refs}`). `ids_digest` is the canonical digest of `tests/regression/governance_ids.json`, and `refs` is the list of `{fixture_id, governance_refs[]}` for this run's `fixture_ids`, sorted by `fixture_id`. Because `governance_refs[]` is not included in `fixture_set_digest`, runs whose links changed are distinguished by this value | TASK-13 |
| `candidate_digest` | canonical digest(list of bundle files excluding the signature file, with the SHA-256 of each file) | TASK-14 `packages/bundles` |
| `artifact_digest` | SHA-256(bundle tarball, including `.signatures.json`) | TASK-14 |
| `payload_digest` (AuditEvent) | canonical digest(AuditEvent fields excluding `payload_digest` and `received_at`) | TASK-07 |
| `decision_input_digest` | canonical digest(sanitized OPA input) | TASK-04 |
| `client_request_key_digest` | SHA-256(`client_request_key`) | TASK-04 |
| `token_digest` | SHA-256(session token) | TASK-03 |

### Observation IDs and abandoned range digest

TASK-07 and TASK-09 producers and receivers share the following fixed UUIDv5 namespaces. They are not regenerated per environment, node, or deployment.

| Constant (`packages/canonical/`) | UUID | Reproduction input |
| --- | --- | --- |
| `NS_AGENTARIUM_KERNEL` | `62aec079-204c-5723-a898-7fa567e82eb4` | UUIDv5(URL namespace, `https://github.com/Beaver-Dam-Community/Agentarium/kernel`) |
| `NS_AGENTARIUM_LIFECYCLE` | `690f05df-a5fe-51bb-8f23-99c4492afc61` | UUIDv5(URL namespace, `https://github.com/Beaver-Dam-Community/Agentarium/lifecycle`) |
| `NS_AGENTARIUM_NETPOL` | `83cab43f-080b-5fba-830d-37c97ec7be5c` | UUIDv5(URL namespace, `https://github.com/Beaver-Dam-Community/Agentarium/network-policy`) |

These URLs are fixed names for namespace generation and are not fetched over the network during computation. The `record_id` of a NetworkPolicyRecord is built from `NS_AGENTARIUM_NETPOL` and the name `cluster_uid/node_uid/source_epoch/source_sequence`, and the two UUIDs must be in lowercase canonical form (`canonical.NetworkPolicyRecordID`). The record name is the UTF-8 concatenation of `sensor_id/source_epoch/source_sequence` or `source_id/source_epoch/source_sequence` from the existing contract. The sequence is a decimal string without leading zeros, in the range 1..2^53−1. The source identifier and epoch must be non-empty, valid UTF-8 strings of 16KiB or less each. A `/` in the source identifier is preserved as is, but `/` is not allowed in the epoch so that boundaries do not become ambiguous. No Unicode normalization or URL escaping is added to existing strings. The `sensor_id` of a kernel ID is the same identifier as the `source_id` confirmed by [TASK-07 batch source authentication](TASK-07-audit-store.md#33-kernellifecycle-receive-ack-and-loss-boundary). The receiving server uses this value, set in the mTLS registration, for both kernel IDs and `range_digest` recomputation, and does not accept a record whose `sensor_id` differs.

`range_digest` is the lowercase hex JCS SHA-256 of an object that contains **only the following six fields**.

```json
{"source_id":"sensor-a","stream":"kernel","source_epoch":"boot-instance","from_seq":2,"to_seq":4,"reason":"record_rejected"}
```

- `source_id` is set by the receiving server from the mTLS registration. The identity sent in the body is not trusted as is.
- `stream` is one of `kernel`, `lifecycle`, or `network_policy` (`/internal/network-policy/records:batch`), depending on the receiving endpoint.
- `source_epoch` equals the batch's epoch, and `1 <= from_seq <= to_seq <= 2^53−1`.
- `reason` is a non-empty, valid UTF-8 string of at most 16384 bytes (16KiB). It is included exactly as sent, and no new reason enum is created.
- `range_digest`, batch ID, receipt time, and gap ID are not included in the preimage. Therefore retransmissions with the same source, stream, epoch, range, and reason have the same digest.

The digest of the example above is `9cb10cb92932d7e31399153b4ba6906a113b3d81eb7a1a98af571c56f212f2c6`. The fixed vectors are kept in `packages/canonical/testdata/observation_vectors.json`. This definition is an ID/digest contract and does not replace source authentication, allowed reasons, overlapping ranges, or watermark handling.

### Lifecycle source authentication and epoch

The lifecycle receiving source is determined by the `SourceBinding {source_id, namespace, ksa, principal}` registered at install time and the verified exact service SAN. The identity in the body is not trusted, and `source_kind` is derived from the trusted KSA. Source/grant rows are not manually added for each new node or replica.

| source_id (exact SAN) | namespace / KSA | source_kind |
| --- | --- | --- |
| `spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder` | agent-sensors / lifecycle-recorder | runtime |
| `spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher` | agent-observe / pod-watcher | pod_watcher |

`producer_event_grants(source_id,'lifecycle_recorded','*')` is registered for each source. `*` is a literal for observation originals and is not a tenant wildcard. This shared source applies only to observation originals, and the replica-specific source_id of ControlHealthLease is maintained. This is within the scope of the existing single-PKI environment, and separate clusters using the same SAN are not automatically merged into the same DB. No new node SANs or kernel principals are created.

The TLS handler verifies the leaf chain/clientAuth/validity period/exact URI SAN, and then passes only the leaf's serial and SAN to the restricted function. Authentication arguments are not accepted from the body/header.

```sql
identity.audit_source_certificate(
  certificate_serial text, exact_san text, requested_boot_hash text DEFAULT NULL
) RETURNS TABLE(namespace text, ksa text, node_uid uuid,
                certificate_boot_id text, historical_boot_id text);
health.audit_source_current_boot(node_uid uuid, certificate_boot_id text)
  RETURNS boolean;
audit.ingest_lifecycle_batch(
  source_id text, batch jsonb, certificate_serial text, exact_san text,
  writer_version text, writer_epoch text
) RETURNS jsonb;
```

- The identity function returns a single row only when exact serial/SAN, `issued_at <= DB now < expires_at`, `revoked_at IS NULL`, and the service role and principal/KSA match of an enabled registered workload are verified. serial uses the same hex normalization as the issuance API. For the optional `requested_boot_hash`, only the actual boot_id matching SHA-256(UTF-8 boot_id) from retained prior-issued certificates of the same SAN/node_uid is returned as `historical_boot_id`. If there is no evidence, it is NULL. Expiration/revocation of past certificates does not erase the boot evidence verified at the time of issuance, but authenticating currently with that certificate is rejected. Issuance metadata is not deleted before the WAL/original retention period (initially 30 days).
- The health function returns only whether there is a match with a non-retired current node/boot, and a non-existent boot is false. Observation can be received for all of preparing/ready/held, but this does not release the hold. Only lifecycle **runtime and kernel sources (tetragon)** call it, and existing node bootstrap precedes it. Health bootstrap/current_boot is not required for watchers. system-pool execution, node migration, and cert node/boot NULL are also allowed as long as the cert is valid, the KSA is enabled, and the scope is permitted.
- Both lookup functions are SECURITY DEFINER owned respectively by the existing identity object owner and `health_owner`. Revoke PUBLIC EXECUTE and grant EXECUTE and necessary schema USAGE only to `audit_writer` and `audit_owner`. A fixed search_path and fully qualified object names are used. Permissions to SELECT identity/health base tables or query certificate PEMs, tokens, or sessions are not added.
- ingest is a SECURITY DEFINER owned by `audit_owner`, and only `audit_writer` executes it. It checks the proxy registration and writer membership of `session_user`, `source_id = exact_san`, and installed producer grants, and re-verifies the cert and runtime current boot within the same transaction. Lock waits are finitely bounded. writer is the sole trusted proxy, and SQL arguments do not prove TLS itself. If an existing 2-argument function is installed, remove its EXECUTE or replace it with a wrapper providing equivalent verification.
- `writer_version` and `writer_epoch` are the receiver's startup configuration/version and durable process epoch, and are not HTTP body fields. The receiver audit source is obtained from the corresponding session_user row in `db_role_sources`, and registration of source_id is required even if proxy=true. Do not confuse this with the client's observation source. The watcher scope is a wire field specified below.

In the existing `audit.ingest_watermarks`, runtime provenance `node_uid uuid NULL`, `boot_id text NULL` and watcher provenance `watch_scope text NULL` are placed. A binding is created only in the initial acceptance transaction, is maintained as immutable thereafter, and only audit_owner ingest functions write to it. There is no separate per-node registry.

| Source | source_epoch encoding | Initial binding and replay |
| --- | --- | --- |
| runtime | `<node_uuid_32hex><sha256_boot_64hex><instance_uuid_32hex>` | Segment lengths 32/64/32, offsets 32/96. Lowercase hex with only UUID hyphens removed, boot hash is SHA-256 of the entire UTF-8 original. A new instance UUID for each new process |
| pod_watcher | `<instance_uuid_32hex>_<durable_restart_counter>` | Durably retains instance/counter and increments on each restart. counter is 1..2^53−1; if unrecoverable, do not truncate and reuse |

The runtime epoch is 128 bytes and the watcher is at most 49 bytes, satisfying WAL's `^[A-Za-z0-9_-]{1,128}$`. The original boot string is maintained in records/certs/bindings and Unicode normalization is not performed. The exact SAN is also within the existing 16KiB upper limit.

1. An unseen current runtime epoch must match the current cert node/boot, the current health boot, the epoch node/boot hash, and the node/boot of the records. The same proof is required even for an initial abandoned batch without records.
2. An already-bound historical runtime epoch is replayed with a **currently** valid cert/current boot of the same node UID. The original boot/epoch/sequence/bytes are preserved, and unacked sequences not yet in the DB can also be accepted. The binding is not overwritten with the current boot, nor is it authenticated with an old cert.
3. For a historical epoch that is WAL fsync → server failure → reboot → **first upload**, an initial binding can be created if there is evidence from the current same-node cert and a retained prior-issued-cert with the identical SAN/node/boot-hash. The node/boot of the records must also match that evidence. If both the binding and prior evidence are absent, or if the node UID differs, it is rejected as a recovery target and the watermark is not advanced. It is not registered based solely on the old boot string provided by the client.
4. A **top-level `scope` is required** in a watcher batch and is included in batch_digest. The installed allowlist is checked; if cursor exists, cursor.scope must match, and if it is a namespace scope, records.namespace must also match. The initial watch_scope is pinned, and record-only/range-only/empty batches also require the same scope. The scope is fsynced to WAL metadata to maintain the original value upon restart/replay. An unknown scope is not inferred from current settings. Do not include scope in runtime batches.
5. The watcher record node/boot is an observation target and is not compared with the node executing the watcher. Even if restarted on a different node, an old/unseen epoch can be replayed with a current same-SAN cert and the allowed original scope. Separate security principals per scope are not created among replicas of the same KSA. Replaying past originals is not an authorization to roll back current checkpoints.

Bindings and prior issuance evidence are trust boundaries for source/node/boot and do not independently prove the WAL contents or the claimed source_time itself. Epoch bindings are not GCed before the WAL/original retention period.

### Kernel source authentication and epoch

The kernel receiving source is a single exact service SAN from the TASK-09 exporter: `spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon` (agent-sensors / tetragon, including the exporter sidecar). The `sensor_id` of KernelEvent is identical to this source_id. At install time, `SourceBinding` and `producer_event_grants(source_id,'kernel_event_observed','*')` are registered, and source/grant rows are not added for each new node. No new kernel principals are created.

```sql
audit.ingest_kernel_batch(
  source_id text, batch jsonb, certificate_serial text, exact_san text,
  writer_version text, writer_epoch text
) RETURNS jsonb;
```

- Authentication arguments, `writer_version`, `writer_epoch`, the use of the two lookup functions, and function owner, EXECUTE, search_path, and lock restrictions are identical to the rules of `ingest_lifecycle_batch` in Lifecycle above. Only `audit_writer` executes it, and a 2-argument signature is not installed.
- `source_epoch` uses the Lifecycle runtime encoding (`<node_uuid_32hex><sha256_boot_64hex><instance_uuid_32hex>`). The rules for initial binding, current boot verification, bound historical epoch replay, and first upload based on retained prior-issued-cert evidence (items 1–3 below the table above) are also identical to runtime. The record's `node_uid` and `boot_id` must match the binding. The same proof is required even for an initial abandoned batch without records.
- Batches do not have `scope` or `cursor`. The stream of ingest_watermarks is `kernel` and `watch_scope` is NULL.
- The receiver atomic audit of an abandoned range uses the rules below as is, with gap `stage` as `kernel_sensor_export` and the payload's `stream` as `kernel`.
- Ingress applies both node CIDR `ipBlock` and exact SAN checks (TASK-07 3.3).
- **Certificate issuance path:** The hostNetwork `tetragon` exporter receives service SAN certificates via the `/internal/workload-certificates` relay of the gateway in the node CIDR (TASK-03 3.3.2, TASK-06 egress table). Since the identity service records the node/boot of Pod `spec.nodeName` in the issuance record, `identity.audit_source_certificate` returns the node/boot of this certificate. This path is used only for agent-sensors Pods running with hostNetwork. Because `lifecycle-recorder` runs on the Pod network, it requests workload-identity directly (TASK-06 3.1 egress table, TASK-09). When migrating other workloads to the Pod network, this list and the egress table are also updated together.
### Lifecycle checkpoint revision CAS

Because the Pod watcher's resourceVersion is opaque, order comparison does not prevent cursor regression. Durable revision CAS is used. The following are explicit wire fields.

| Path | Field |
| --- | --- |
| GET `/internal/lifecycle/checkpoints?scope=` success | `{scope, resource_version, committed_at, checkpoint_revision}` |
| Optional cursor of watcher batch | `{scope, resource_version, expected_checkpoint_revision}` |
| Successful checkpoint of batch response | `{scope, resource_version, checkpoint_revision}` |

GET does not add source_id to the response. If absent or outside the allowed scope, it is `404 RESOURCE_NOT_FOUND`, and the logical revision of a nonexistent checkpoint is 0. The expected value is 0..2^53−1, and the stored revision is 1..2^53−1. cursor/expected is also included in batch_digest.

`audit.lifecycle_checkpoint(source_id text, scope text) RETURNS TABLE(scope text, resource_version text, committed_at timestamptz, checkpoint_revision bigint)` is a SECURITY DEFINER owned by audit_owner. Revoke PUBLIC EXECUTE and grant EXECUTE only to audit_writer. It queries only a single source/scope by verifying fixed search_path/fully qualified object names, session_user proxy registration, and writer membership. Base-table SELECT by writer is prohibited. The handler verifies the currently valid pod-watcher cert/enabled KSA and the SourceBinding/scope allowlist, and passes only that source/scope. There is no health boot condition for the watcher host.

`watch_checkpoints` stores a nullable `lifecycle_event_id` FK and `checkpoint_revision`, `last_batch_id`, and `last_batch_digest`. Empty LIST/bookmarks can have FK NULL and do not create synthetic lifecycle events. The FK of the previous actual row can be retained. If existing checkpoints exist, the migration must specify the initial revision and the actual metadata backfill policy, and must not fabricate an arbitrary batch_id as the original request.

1. Serialize up to the initial INSERT of the same source/scope with a bounded lock, and perform CAS in the same transaction as records/outbox/ranges.
2. If both the current last_batch_id and batch_id, and last_batch_digest and batch_digest are identical, it is a retry of the immediately preceding request. Return the existing resourceVersion/revision/committed_at as is, without incrementing the revision. If it is the same last_batch_id with a different digest, reject the cursor change.
3. Other requests store the cursor with revision+1 only when expected_checkpoint_revision matches the current revision, all records are accepted/duplicate, and the contiguous watermark condition is satisfied. cursor-only requires acked_through=max_seen for the corresponding epoch, and an empty epoch is 0=0. The producer must complete all LIST pages and preceding records. The presence of records not yet received by the DB cannot be proven by this condition alone. Revision overflow is fail closed.
4. A stale expected COMMITs records/outbox according to existing idempotency rules, but returns `checkpoint=null`. It does not create a new HTTP error and maintains the partial-200 rule. A arriving late after B's commit cannot overwrite the current cursor. DB/audit failures roll back entirely, and ack is sent only after COMMIT.

The producer **fsyncs the cursor and expected revision to the same durable batch** and preserves both upon retransmission. Do not attach the latest revision obtained via GET after a stale checkpoint=null to an old cursor. Resume WATCH/LIST from the server's current cursor to create a new batch. If the original cursor/expected from the historical WAL cannot be recovered, replay only the original records without a cursor, and start the new WATCH from the current checkpoint obtained via GET. Preserve the original ID/epoch/sequence.

Maintain M2's single watcher operation. This rule prevents regression from delayed retries and is not an HA leader election API. Only the last_batch metadata of the current cursor is preserved, and a separate persistent incoming receipt ledger or export_batches reuse is not required.
### Receiver atomic audit of abandoned ranges

**Scope applied in this implementation:** The concrete authentication and server metadata path of the receiver atomic write below applies to the lifecycle stream for which the 6-argument `ingest_lifecycle_batch` is defined. The requirement that kernel also store the gap, the two audit events, the outbox, and the watermark in the same transaction remains. However, the existing 2-argument `ingest_kernel_batch(source_id, batch)` has no contract for passing the verified caller and the receiver `writer_version` and `writer_epoch`. Until kernel source/epoch provenance and the trusted server argument signature are settled in [#92](https://github.com/Beaver-Dam-Community/Agentarium/issues/92), this 2-argument path is not activated, and it is not substituted by copying the sender epoch, an arbitrary receiver epoch, or implicitly applying the lifecycle rules.

TASK-09 declares an abandoned range in the batch, and for a declaration verified by the TASK-07 receiver, the gap, abandoned_ranges, `sequence_range_abandoned`, `observation_gap_recorded`, and the two outboxes are recorded in one transaction. TASK-09 does not separately publish the same business event. The order is source/epoch authentication → bounded watermark lock → determination of an exact-match resend of the same range → gap/range INSERT → two audit_append/outbox → contiguous watermark advance → COMMIT. Every audit/DB failure is rolled back, and a separate health HTTP call does not substitute for atomicity.

| AuditEvent metadata | Assignment |
| --- | --- |
| event_id | Two random UUIDs in the first accepting transaction. Durably linked to sequence_event_id/gap_event_id of abandoned_ranges |
| source_id | The receiver audit source that the installer assigned to the writer session_user row of db_role_sources. Required even if proxy=true, and different from the client observation source |
| source_version / source_epoch | Server writer_version / writer_epoch. The epoch is a durable restart counter exclusive to the replica instance and distinguishes each process; the sender epoch is not copied |
| source_sequence | null. Uses the COMMON optional path, and raw from_seq/to_seq are not reused as a business sequence |
| source_time / received_at | DB time when the declaration was first accepted / statement_timestamp() inside audit_append. The occurrence time of the actually lost original is not estimated |
| tenant / authenticated_actor | Only for the two operational events: literal `*` / `service:<namespace>/<ksa>` of the verified requester |
| schema_version / evidence_refs | 1 / only confirmed existing references, otherwise [] |
| Optional workload, session, action, request, attempt, policy, catalog | Unconfirmed values are null. Not attributed arbitrarily |
| payload_digest | Existing AuditEvent JCS rule (excluding payload_digest and received_at) |

The DDL given in TASK-07 is the target state after the new migration is applied and does not represent the current structure of already merged migrations. The new migration must add a CHECK that requires a nonempty `source_id` for proxy rows of `db_role_sources` as well, install `abandoned_ranges.sequence_event_id` and `gap_event_id` as NOT NULL, change `producer_task` to TASK-07 in the `event_types` row with `event_type = sequence_range_abandoned`, and add `source_id` and `stream` to the required payload. Existing migrations are not modified. If existing abandoned rows exist, a migration plan that preserves their linkage and provenance to the two actual audit events is needed first, and they are not backfilled with random UUIDs or newly created past events. Without such grounds, the migration is aborted.

For NULL/empty values of existing proxy sources, the migration is applied after the installer registers the actual receiver source, and they are not backfilled with the producer source or arbitrary values. Ingest does not receive the receiver source as an HTTP/function argument; it reads it from the corresponding `session_user` row and verifies it again.

The installer adds the exact grants `(sequence_range_abandoned,'*')` and `(observation_gap_recorded,'*')` to the receiver source. The lifecycle_recorded grant does not substitute for these. `*` is not a wildcard or a read permission over all tenants, and it is not automatically exposed in tenant-filtered timelines. The existing writer proxy/audit_producer membership boundary is kept.

`sequence_range_abandoned.safe_payload` is the original observation `source_id`, `stream` (kernel/lifecycle), sender `source_epoch`, `range {from_seq,to_seq}`, the verified declaration `reason`, and the existing six-field `range_digest`. The payload epoch is the sender's, and the envelope epoch is the receiver's; they differ. source_id/stream are required fields of the registry, and this does not mean new caller audit metadata is accepted. `observation_gap_recorded.safe_payload` is `gap_id`, `stage`, `reason = SEQUENCE_RANGE_ABANDONED`, `sequence_range {from_seq,to_seq}`, `count_quality = exact`.

If to_seq/reason/range_digest of the same natural key `(source_id,stream,source_epoch,from_seq)` are all identical, the existing gap and the two event IDs, times, and epochs are reused. A different body or overlap is EVENT_ID_CONFLICT. Because duplicates and contention are handled in the audit_owner-owned abandoned_ranges/watermark, RETURNING/ON CONFLICT is not used on the health INSERT. IDs from a rolled-back transaction are not committed facts, so they can be reassigned on retry.

This health INSERT permission is not yet in the health migration on main. Before TASK-07 ingest is activated, the schema USAGE and column-limited INSERT below must be granted by a new migration owned by TASK-10. audit_owner is a NOLOGIN function owner and is not given through role membership of the runtime login. health INSERT/SELECT/UPDATE are not added to audit_writer.

```sql
GRANT USAGE ON SCHEMA health TO audit_owner;
GRANT INSERT (gap_id, stage, reason, node_uid, boot_id, source_id,
  source_epoch, sequence_from, sequence_to, range_digest,
  start_at, end_at, affected_workloads, loss_count, count_quality,
  evidence_refs, recovery_state, created_by)
ON health.observation_gaps TO audit_owner;
```

created_at is the DB default. stage is kernel_sensor_export/lifecycle_capture depending on the stream, recovery_state is unrecoverable, and created_by is TASK-07. The runtime node/boot is obtained from the verified epoch binding; if the watcher's target is unknown, it is left NULL and not substituted with the watcher host. loss_count=`to_seq-from_seq+1` and count_quality=exact prove only the **number of allocated producer sequences** and do not represent the number of kernel losses before that.

For a declaration without an actual loss time, start_at is the time of first detection/acceptance and end_at is NULL. Consumers must not judge the period before the detection time as a normal observation interval, and must use the source/epoch/sequence range as the basis for the loss. affected_workloads=[] does not mean no impact but undetermined, and the health decision is not arbitrarily escalated to a specific tenant/session.

**Export of null-sequence events:** Events without a sequence are covered by the manifest's `outbox_range`, `record_count`, and batch digest, and only records with a sequence are included in `sources[]` ([TASK-07 3.2.1](TASK-07-audit-store.md#321-confirmed-export-items)). No separate sequence allocator is created.

<a id="policy-decision-contract-ref"></a>

## Policy decision contract

Rego makes the decision. OPA is embedded in the gateway (`services/gateway/`, Go) process as the `github.com/open-policy-agent/opa/v1/rego` library, with no sidecar or loopback REST. OPA's configuration-based bundle download (`v1/sdk`) is not used either. Bundle loading is handled by the shared Go package `packages/policyloader/` (TASK-04), in the order below. The exact call form is defined by [TASK-04 3.1](TASK-04-policy-gateway.md#31-authentication-recording-rules-embedded-opa-loading).

1. Every 2 seconds the gateway reads the `desired_bundle` row ([Policy release contract](#policy-deployment-contract)), and if it has changed, fetches the tarball from that row's `object_uri`. It does not look for "the newest object".
2. It confirms that the SHA-256 of the tarball equals `desired_bundle.artifact_digest`.
3. It reads the bundle with `NewCustomReader` of `v1/bundle`, specifying `WithBundleVerificationConfig(NewVerificationConfig(keys, keyID, scope, nil))`. In the OPA source, a bundle without `.signatures.json` is rejected only when `VerificationConfig.KeyID` is not empty, so `keyID` is required ([bundle.go](https://github.com/open-policy-agent/opa/blob/main/v1/bundle/bundle.go) `checkSignaturesAndDescriptors`). `WithSkipBundleVerification` is not used. The production gateway trusts only keyID `prod-v1`.
4. If the read `Bundle.Manifest.Revision` is empty, the bundle is rejected.
5. A prepared query is built with `rego.ParsedBundle` and `PrepareForEval` ([opa/v1/rego](https://pkg.go.dev/github.com/open-policy-agent/opa/v1/rego)). On failure, the previous set is kept and `policy_bundle_load_failed` is recorded.
6. The set "prepared query, `Manifest.Revision`, `artifact_digest`, `data.catalog`" is swapped atomically, and `policy_bundle_loaded` and the lease (`loaded_artifact_digest`) are reported. Each evaluation uses the single set present at its start until the end. Gateway normalization (TASK-02) also uses the `data.catalog` of the same set as the active catalog.

A gateway that has not loaded any bundle lowers readiness and rejects every request with 503 `POLICY_UNAVAILABLE`. Before evaluation, the set's revision is compared with `active_policy.expected_opa_revision`; if they differ, no evaluation is performed and the request is handled as 503 `POLICY_VERSION_MISMATCH`. The bundle `revision` is a string field of the `.manifest` file ([OPA bundles](https://www.openpolicyagent.org/docs/management-bundles)). The API names and behavior above were confirmed against the OPA main branch source, and must be rechecked against the OPA version to be pinned.
### OPA input and result

The input contains only the following 5 keys. Field names are identical to the names read by Rego (`policies/gateway/decision.rego`). If even one is missing, Rego denies with `CONTEXT_INCOMPLETE`.

| input key | Field | Source |
| --- | --- | --- |
| `envelope` | Entire ActionEnvelope (including `action_id`) | gateway normalization |
| `verified_session` | Common: `kind(user/service), session_id, authenticated_actor, state, tenant, expires_at, allowed_operation_ids[]`. `user`: `workload_id`. `service`: `caller_principal, service_scope {profile, issue_id?, candidate_id?, change_id?, snapshot_id?, action_id?}`. For service sessions as well, the key name is `session_id` and the value is `service_session_id`. The `authenticated_actor` of a service session is `service:<namespace>/<ksa>` | `sessions`·`service_sessions`. `allowed_operation_ids` is `sessions.allowed_operation_ids` for user sessions, or an empty array for service sessions, and Rego determines it via `data.service_profiles[profile]` |
| `approval_snapshot` | `approval_id, action_id, revision, approval_kind, session_id, authenticated_actor, allowed_operation, canonical_target, disclosure_fields, content_digest, max_actions, used_actions, policy_epoch, expires_at, revoked_at` or `null` | The latest unexpired, unrevoked revision found in `approvals` by `action_id`. If none exists, `null` |
| `workload_data_state` | `data_class_high_water, data_sources[]` | The `(workload_id)` row for user sessions, or the `(service_session_id)` row for service sessions. If none exists, `{"data_class_high_water": "none", "data_sources": []}` |
| `control_health` | `evaluated_at, active_artifact_digest, active_holds[] {hold_id, scope, scope_id, reason}, required_leases[] {component, source_id, observed_state, lease_until, active_version}, activation_probe` (`{activation_probe_id, change_id, service_session_id, action_id, target_epoch, expires_at}` or `null`). `active_artifact_digest` is the bundle `artifact_digest` of the evaluation bundle | `holds`·`control_health_leases`·`activation_probes`. Selected according to the rules below |

- **Fact reading:** The gateway reads the above facts in a single read-only `REPEATABLE READ` transaction and populates `evaluated_at` (RFC 3339) with the `statement_timestamp()` of that transaction. Rego uses this value as the evaluation timestamp instead of `time.now_ns()`, and evaluation replay also uses the stored value as is.
- **Hold selection:** The gateway includes unreleased holds from the scopes `global`, `target` (`canonical_target.target_id`), `session` (user `session_id` or `service_session_id`), and the `workload` scope for user sessions. The `node` scope cannot be known at the evaluation time, so the coordinator reservation transaction checks it.
- **Required leases:** Every request requires `gateway`, `coordinator`, `audit-db`, `audit-export`, and the `adapter` for the corresponding operation (catalog `adapter_id`). `receiver.submit` adds `destination-evidence`, and user sessions add `node-sensors` of the node where the workload is scheduled. At least one valid lease is required per component.

A canonical example of a Rego unit test fixture is as follows (synthetic values, receiver approval path).

```json
{
  "envelope": {
    "schema_version": 1, "action_id": "6f1c…", "request_id": "0a9e…",
    "authenticated_actor": "google:1029…", "session_kind": "user", "session_id": "3b2d…",
    "workload_id": "agent-exec/agent-runtime", "endpoint_id": "test-receiver-v1",
    "operation_id": "receiver.submit",
    "canonical_target": {"target_id": "receiver-main", "route_id": "submissions"},
    "environment": "prod", "tenant": "demo", "disclosure_fields": ["summary"],
    "data_class": "synthetic", "data_sources": ["k8s.pods.logs"],
    "content_digest": "9c1e…", "content_ref": "9c1e…", "bytes": 412,
    "limits": {"request_bytes": 65536}, "catalog_digest": "51aa…", "catalog_version": "2026-10-11.1",
    "canonicalization_version": "v1", "raw_body_digest": "77d0…", "action_digest": "e2b4…"
  },
  "verified_session": {
    "kind": "user", "session_id": "3b2d…", "state": "claimed", "tenant": "demo",
    "expires_at": "2026-10-11T10:30:00Z", "authenticated_actor": "google:1029…",
    "workload_id": "agent-exec/agent-runtime",
    "allowed_operation_ids": ["k8s.pods.list", "k8s.events.list", "k8s.pods.logs", "receiver.submit", "model.generate"]
  },
  "approval_snapshot": {
    "approval_id": "a71f…", "action_id": "6f1c…", "revision": 1, "approval_kind": "action",
    "session_id": "3b2d…", "authenticated_actor": "google:1029…", "allowed_operation": "receiver.submit",
    "canonical_target": {"target_id": "receiver-main", "route_id": "submissions"},
    "disclosure_fields": ["summary"], "content_digest": "9c1e…",
    "max_actions": 1, "used_actions": 0, "policy_epoch": 7,
    "expires_at": "2026-10-11T10:05:00Z", "revoked_at": null
  },
  "workload_data_state": {"data_class_high_water": "synthetic", "data_sources": ["k8s.pods.logs"]},
  "control_health": {
    "evaluated_at": "2026-10-11T10:01:00Z", "active_holds": [],
    "required_leases": [
      {"component": "gateway", "source_id": "policy-gateway-7d9f", "observed_state": "healthy", "lease_until": "2026-10-11T10:01:15Z"},
      {"component": "adapter", "source_id": "receiver-sender-5c2a", "observed_state": "healthy", "lease_until": "2026-10-11T10:01:14Z"}
    ],
    "activation_probe": null
  }
}
```

Expected result: `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["approval.allow.v1"], "evaluated_rule_ids": ["input.required_keys.v1", "catalog.endpoint_registered.v1", "catalog.digest_match.v1", "session.binding.v1", "target.scope.v1", "disclosure.receiver.v1", "data_class.high_water.v1", "approval.binding.v1", "approval.usable.v1", "hold.blocking.v1", "health.required_leases.v1"]}`. In actual fixture files, full UUIDs and digests are included without ellipsis.

**Rego results and decision rules:**

- The result is `{verdict, reason_codes, matched_rule_ids, evaluated_rule_ids}` and is validated against a strict schema. `matched_rule_ids` contains the rule IDs that served as the basis for the verdict and must not be empty. `evaluated_rule_ids` contains all check rules evaluated and applied to that operation (including passing ones).
- All rules have stable ID constants in the format `<domain>.<rule>.v<number>`. `standing.*` and `probe.*` IDs use `standing_rule_id` from policy data as is. Changing or removing a rule_id requires a new bundle and regression testing.
- There are four bases for allowing: approval (`approval.allow.v1`), user session standing rule (`standing.*`), service session profile (`service.scope_allow.v1`: where `verified_session.kind = service` and operation, target, and model profile are within `data.service_profiles[profile]`), and activation probe (`probe.activation.v1`). If a service session request falls outside the profile, it is denied with `SERVICE_SCOPE_DENIED` and does not become `approval_required`. Service sessions cannot receive approvals.
- From the result, the gateway populates GatewayDecision's `decision_basis` (`approval`, `standing_rule`, `service_scope`, `activation_probe`) and the corresponding ID (`approval_id`, `standing_rule_id`, `service_session_id`, `activation_probe_id`). The original Rego result is retained as is in `rego_result`, while IDs appended by the gateway after Rego are separated into `gateway_added_rule_ids`. Currently, the only appended ID is `intent.divergence_escalation.v1` from intent check escalation. The final `matched_rule_ids` = `rego_result.matched_rule_ids` ∪ `gateway_added_rule_ids`.
- Intent check escalation is applied by the gateway after the Rego evaluation only in the direction of `allow → approval_required`, and an escalated decision has `decision_basis = null`, `reason_codes = ["APPROVAL_REQUIRED", "INTENT_DIVERGENCE_ESCALATED"]`, and `standing_rule_id = null`. The original standing rule ID remains only in `matched_rule_ids` and `rego_result.matched_rule_ids`. Adapter preflight is the secondary defense.
**patch kind and target rule_id:** The policy proposal validator requires both "target rule_id ∈ `evaluated_rule_ids` of the evidence decision" and "matches the table below". The data paths and patch schema are in [Appendix A](#appendix-a-policy-data-and-patch-schema).

| patch kind | data path | target rule_id | Evidence check |
| --- | --- | --- | --- |
| `receiver.allowed_disclosure_fields` | `/receiver/allowed_disclosure_fields` | `disclosure.receiver.v1` | `evaluated_rule_ids` of the evidence decision |
| `targets` | `/catalog/targets/<target_id>/{operation_ids,allowed_cidrs,max_data_class}` | `target.scope.v1`, `catalog.endpoint_registered.v1`, `data_class.high_water.v1` | `evaluated_rule_ids` of the evidence decision |
| `standing_rules` | `/standing_rules/<standing_rule_id>` | That `standing_rule_id` | `matched_rule_ids` or `evaluated_rule_ids` of the evidence decision |
| `adapter_constraints` | `/adapter_constraints/<adapter_id>` | `adapter.preflight.v1` (adapter check) | Evidence `preflight_passed` or `preflight_rejected` event |
| `policy.draft.create` | `/standing_rules/<existing id>/operation_ids` and `/limits`, `/catalog/targets/<id>/operation_ids` (only remove and narrowing replace) | The narrowed target `standing.*`, `target.scope.v1` | An allow decision within the period whose `evaluated_rule_ids` contains that rule. `permission_widening.widened = false` is required |
| `sensor_rules` | `/sensor_rules/<rule_name>` | None (kernel rules) | Only operator `operator_patch`. Cannot be proposed by the model |

The validator rejects any patch that touches `/standing_rules/probe.activation.v1` or `/service_profiles`, regardless of kind.

**Recording of normalization-stage rejections and evaluation failures:**

| Case | HTTP and reason code | Rows written | event |
| --- | --- | --- | --- |
| Authentication failure | 401 `AUTH_REQUIRED` | None (rate limit log only) | None |
| The envelope cannot be built (body or per-operation schema violation, unregistered `operation_id` or `target_id`, size exceeded) | 422 `SCHEMA_INVALID`, 403 `ENDPOINT_NOT_REGISTERED`, 413 `BODY_TOO_LARGE` | No action or decision | `request_rejected` |
| The envelope exists but is rejected at the normalization stage (`CONTENT_PATTERN_DENIED`) | 403 | Action and a decision with `decision_stage = normalize` (`matched_rule_ids = ["normalize.content_pattern.v1"]`, `rego_result` and `opa_bundle_revision` null) | `request_received`, `policy_decided` |
| Revision mismatch or OPA evaluation failure | 503 `POLICY_VERSION_MISMATCH`, `POLICY_UNAVAILABLE` | No action or decision. Can be resubmitted with the same `client_request_key` | `policy_evaluation_failed` |
| Normal evaluation | Depends on the decision | The transaction below | `request_received`, `policy_decided`, and if needed `approval_requested`, `dispatch_enqueued` |

`normalize.endpoint_registered.v1` for unregistered operations and targets and `normalize.schema.v1` for per-operation schema violations are TASK-02 `NormalizeError.rule_id` values. Because the envelope cannot be built for these errors, they follow the `request_rejected` rule in the table above and are not stored as `matched_rule_ids` of a normalize decision.

When several reason codes occur together, the HTTP status is chosen in the order 503 > 409 > 403 > 422. Deny and approval_required response bodies also contain `request_id, action_id?, decision_id?, verdict, execution_allowed=false, reason_codes`. For `allow`, `execution_allowed=true`.

**Decision storage transaction:** Normal evaluation and normalization-stage rejection COMMIT the following together in one write transaction: `actions`, `action_contents`, `decision_inputs`, `decisions`, `intent_checks` (if present), the update of `activation_probes.action_id`, `execute_requests` (allow only), `audit_append()` (`request_received`, `policy_decided`, and if needed `approval_requested` and `dispatch_enqueued`), and `audit.enqueue_decision_input()`. A state with an action but no decision never occurs. If the COMMIT fails, the result is 503 `STATE_STORE_UNAVAILABLE` and no rows remain.

**Durable dispatch:** `execute_requests(decision_id PK, action_id, adapter_id, state(pending/delivered/expired), attempts, next_attempt_at, lease_until, updated_at)` (TASK-04) is written in the same transaction as the allow decision. The old name `dispatch_queue` is not used. A gateway worker takes rows with `FOR UPDATE SKIP LOCKED` and resends `POST /internal/adapter/{adapter_id}/execute` until the decision's `expires_at`, starting at 200ms and doubling the interval each time; the adapter processes the same decision only once using `adapter_executions`. On expiry the state changes to `expired`, and the runtime receives a new decision through `:reevaluate`.

**Decision input storage:** For every decision, the gateway stores the sanitized OPA input in `decision_inputs` and records `decision_input_ref` and `decision_input_digest` in the GatewayDecision. The retention period is 30 days and the owner is TASK-04. Secrets, raw logs, and raw content are not included; only `content_digest` is included. Export to the regression project follows the export rules of the [policy deployment contract](#policy-deployment-contract).

### Decision Replay (decision_replay)

| Item | contract |
| --- | --- |
| Owner and tool | TASK-13, Go `tools/decision-replay/` (the same `packages/policyloader/` and the same OPA module version as the gateway) |
| Timing | Runs as the first step of a regression run, before the E2E tests |
| Input | `decision_inputs` of decisions within the last 7 days with `decision_stage = opa` and `policy_bundle_id` equal to the baseline bundle, up to 5000 entries, newest first. In the regression project, only the exports in the `decision-input-exports` bucket are read |
| Comparison | The Rego results re-evaluated with the baseline and candidate bundles are compared with the stored `rego_result`. `gateway_added_rule_ids` (intent escalation) are excluded from the comparison. If the baseline re-evaluation differs from the stored value, that input is counted as `replay_inconsistent`, and the run as a whole is not invalidated |
| Output | RegressionReport `decision_replay {replayed_count, changed_count, replay_inconsistent_count, excluded_batch_count, changed[] {...}}` |
| Use | Evidence of impact on normal work in the report and the human approval screen. `decision_replayed` event |
| Limits | `release_eligible` is not decided from replay results alone. Because the sanitized input has no raw content, the content checker results use the stored decision facts as they are |

### Permission widening check (permission_widening)

| Item | contract |
| --- | --- |
| Ownership and implementation | Owned by TASK-14 and computed by Go `packages/policydiff/`. The TASK-12 proposal service uses the same check for preview |
| Computation | For each typed data patch, the values before and after applying the patch are compared according to the **comparison rules by kind** below, and changes regarded as widening are listed in `items[] {path, added_values, removed_values}`. Set values are compared by checking whether the new allowed set is a subset of the previous allowed set. Non-set values (numeric limits, data classes, CIDRs, patterns) follow the rules in the table; in this case, `added_values` contains the new value and `removed_values` contains the previous value. If there is at least one entry in `items`, `widened = true` |
| Storage | When the releaser processes `POST /v1/policy-changes`, it stores it as PolicyChange `permission_widening {widened, items}` and records a `permission_widening_checked` event |
| Preview | `POST /internal/policy-diff:check` (owned by TASK-14, callers: proposal service, console): `base_bundle_digest, patch` → `candidate_digest, permission_widening`. Because the releaser creates a pre-signature candidate bundle with `packages/bundles/` and stores it by digest, TASK-12 does not create bundles or compute digests |
| Approval effect | If `widened = true`, the approval screen highlights widened items and requires item-by-item acknowledgement. If omitted, `PERMISSION_WIDENING_ACK_REQUIRED` |
| Limitations | Holds only within the scope of typed patches. It does not use semantic analysis of Rego code changes or formal verification tools (such as Cedar SymCC) |

**Comparison rules by kind:** Targets are the kinds and allowed paths in [Appendix A](#appendix-a-policy-data-and-patch-schema). This table is authoritative and implemented directly by `packages/policydiff/` (TASK-14). It does not analyze the semantics of Rego code.

| kind | Allowed path (Appendix A) | Changes included in `items` |
| --- | --- | --- |
| `receiver.allowed_disclosure_fields` | `/receiver/allowed_disclosure_fields` | The new array is not a subset of the previous array. Added elements are placed in `added_values` |
| `targets` | `/catalog/targets/<target_id>/operation_ids` | Elements are added |
| `targets` | `/catalog/targets/<target_id>/allowed_cidrs` | The new set of CIDRs contains addresses not included in the previous set of CIDRs. Determined by CIDR inclusion relationships, not string comparison |
| `targets` | `/catalog/targets/<target_id>/max_data_class` | The `data_class` rank (`data.data_class_rank`) increases |
| `standing_rules` | `/standing_rules/<standing_rule_id>` (entire) | An `add` of a previously non-existent id is the addition of a new rule, so it is a widening. A `replace` of an existing id is evaluated field by field. If elements are added to `operation_ids` or `disclosure_fields`, it is a widening. If `session_kind` or `profile` changes, or if the `disclosure_fields` field is added or removed, containment is not evaluated and the change itself is included for review. `limits`, `target_pattern`, `data_profile`, and `session_budget` follow the rules in the rows below. A `remove` of a rule is not a widening |
| `standing_rules` | `/standing_rules/<standing_rule_id>/limits` | The number for a key increases, or a previously existing upper limit key is removed |
| `standing_rules` | `/standing_rules/<standing_rule_id>/target_pattern` | The value changes. Because containment relationships between glob patterns are generally not evaluated, the change itself is included for review |
| `standing_rules` | `/standing_rules/<standing_rule_id>/data_profile` | The `data_class` rank increases |
| `standing_rules` | `/standing_rules/<standing_rule_id>/session_budget` | The number increases |
| `adapter_constraints` | `/adapter_constraints/<adapter_id>/max_request_bytes`, `/max_response_bytes` | The number increases |
| `adapter_constraints` | `/adapter_constraints/<adapter_id>/allowed_route_ids` | Elements are added |
| `policy.draft.create` | Narrowing-only paths in Appendix A | No new rules are introduced. The `standing_rules` and `targets` rules above are applied as is. This kind allows narrowing only, maintaining the Appendix A contract that sets the candidate to `rejected` if even a single item appears in `items` |
| `sensor_rules` | `/sensor_rules/<rule_name>` | This is not permission widening, but control weakening. If `enabled` changes from `true` to `false`, a rule is `remove`d, or `selector` changes (containment between selectors is not evaluated), the change is added to `items` to undergo the same item-by-item acknowledgement procedure. Items whose `path` starts with `/sensor_rules/` are distinguished and displayed as "control weakening" on the approval screen |

"The change itself is included for review" means that because it cannot be determined whether permissions were widened or narrowed, it is conservatively added to `items`. If the value remains the same, it is not added.
## State, atomicity, and DB permissions

| Storage unit / owner | Key constraints |
| --- | --- |
| sessions, session_tokens, service_sessions, service_session_counters, issue_candidates, issue_candidate_counters, session_budgets, approval_nonces / TASK-03 | Session PK, actor/workload binding, single use of claim_code, expiry/state, and service session tool budgets. `issue_candidate_counters(issue_id, candidate_id, counter) PK, used_value` is the cumulative usage of one candidate and is shared by all service sessions of that candidate. `approval_nonces(nonce PK, action_id, intent_check_id?, required_ack_finding_ids[], expires_at)` has a TTL of 10 minutes and is single-use. At approval, `acknowledged_findings ⊇ required_ack_finding_ids` is checked against this row. TASK-03 owns the full DDL (types, nullability, FKs, indexes) |
| approvals / TASK-03 | `action_id` column and `(action_id, revision)` unique, immutable contract digest, used/max, `policy_epoch`, revocation, `intent_check_id`, `acknowledged_findings` |
| registered_workloads, certificate issuance records / TASK-03 | `PRIMARY KEY(namespace, ksa)`, issued SAN, serial, and expiry |
| actions, decisions, decision_inputs, intent_checks, execute_requests / TASK-04 | actor/session/client_request_key unique (owned by TASK-04), 409 if `raw_body_digest` differs, immutable decision, `decision_inputs` retained for 30 days. Read view for the evidence collector: `actions_target_view(action_id, tenant, operation_id, canonical_target)` |
| action_contents / written by TASK-04 | Key `(content_digest, action_id)`, retained for 30 days. Read only by the corresponding adapter and the TASK-03 contract renderer |
| action_results, workload_data_state, adapter_executions, model_turns / TASK-05 | The adapter writes them, and the gateway reads `action_results`, `workload_data_state`, and `adapter_executions`. The high-water mark cannot decrease. `model_turns` is read and written only by the model adapter DB role, and is retained until the `max_expires_at` of the corresponding service session or user session, or the `expires_at` of the service session (lookups check the current session state and expiry separately) |
| reservations, attempts, dispatch_permits, activation_probes, attempt_observations / TASK-03 coordinator | `UNIQUE (action_id)` (one reservation per logical action), attempt PK, active partial unique index (`planned, claimed, dispatched, unknown`). `attempt_observations` stores AdapterObservations, PK `(attempt_id, request_ordinal)`, index `(netns_inode, local_addr, local_port)`, `correlation_reader` SELECT |
| active_policy, desired_bundle / TASK-14 (write), TASK-03·04·05 (read) | `active_policy(scope_id = environment, epoch, bundle_id, bundle_digest, artifact_digest, expected_opa_revision, catalog_digest, sensor_release_policies_digest, activated_by_change_id, updated_at)`. `sensor_release_policies_digest` is the expected value of the release-managed TracingPolicies for the TASK-10 drift probe ([TASK-14 3.4](TASK-14-policy-release.md#34-deployment-permissions-and-rollback)). The epoch increases. `bundle_digest` is the candidate digest that the TASK-14 epoch CAS compares and updates, and `catalog_digest` is the catalog digest of the active bundle that the reservation transaction compares. There is no hold field. `desired_bundle` follows the [policy deployment contract](#policy-deployment-contract) |
| holds, control_health_leases, node_boot_generation, component_principals, probe_results / TASK-10 | Scope lookup index for unreleased holds, owning component per reason, and caller SAN → component mapping. control-health owns and updates `node_boot_generation`: it creates a `preparing` row on the first `node-sensors` lease of a new node/boot, sets it to `ready` when the correct-answer probe passes twice in a row, sets it to `held` when a node-scope hold is created, and sets the previous row to `retired` when the boot ID changes. `startup_capture` is taken from the per-node-pool Q0 result in the environment lock; when Q0 was not run, is incomplete, or is missing, it is recorded as `unsupported` together with `startup_capture_measurement = not_measured` ([TASK-16 3.1](TASK-16-delivery-runbooks.md#31-installation-order-and-the-environment-lock)) |
| audit_events, kernel_events, audit_outbox, ingest_watermarks, db_role_sources, watch_checkpoints / TASK-07 | event_id unique, appended only through `audit_append()`, and the same ID with a different body raises a conflict alert. Kernel events go to `audit.kernel_events` (`UNIQUE(source_id, source_epoch, source_sequence)`, tuple index). The outbox distinguishes the source table with `record_kind`. `ingest_watermarks(source_id, stream(kernel/lifecycle), source_epoch, acked_through, max_seen)`. `watch_checkpoints` is updated by the lifecycle batch response |
| lifecycle_events / received by TASK-07, produced by TASK-09 | INSERT-only for original facts. Tombstones are not deleted when the Pod is deleted |
| receiver.receiver_effects, receiver_attempts / TASK-08 | Server-generated PK, the client attempt ID is an ordinary column, and 409 conflict records are written in a separate transaction |
| correlations, lifecycle_intervals (derived) / TASK-10 | Originals are separated from confirmed/inferred relations, with revisions. `lifecycle_intervals` is derived from `lifecycle_events` |
| network_policy_records, network_policy_watermarks, network_findings (derived) / TASK-10 | `network_policy_records` is INSERT-only, and `UNIQUE(node_uid, source_epoch, source_sequence)` prevents duplicates. `network_findings` allows only appending `(finding_id, revision)` and does not accept `confirmed` for `confidence`. The latest revision is in the view `correlation.network_findings_latest` |
| start_permits, start_attempts / TASK-10 start coordinator | Unique consumption per runtime binding, immutable digest, expiry, and matching sensor/guard generation. The agent has no permission to issue, consume, or transition them |
| observation_gaps / TASK-10 (TASK-07 stores abandoned intervals) | Observation stage, affected scope, and recovery evidence. An unknown loss content is not overwritten as normal |
| alignment_results, mismatches / TASK-11 | The only tables TASK-11 writes. Other Tasks' tables are read-only |
| issues, issue_evidence, proposals / TASK-12 | Issue natural key unique, exact candidate digest and state |
| fixture_registry, regression_runs / TASK-13 | Required set digest fixed per scope |
| policy_changes / TASK-14 | Exact diff/hash, tests/approval, and state |
| discovery_candidates / TASK-02 | State transitions and references to reproduction runs |
| credential_bindings / TASK-06 | Secret version allowlist per adapter and operation |

DB roles are separated into authentication, approval, execution coordination, audit append, export, and query. Execution Pods are not given DB credentials. DB access from Python components is mostly reads, and writes go through the owning service's API. The only exceptions are the tables each Python service owns (`intent_checks` for the TASK-04 Python intent checker, `alignment_results` and `mismatches` for TASK-11, `issues` and `proposals` for TASK-12, and `regression_runs` for TASK-13). The limits under DB administrator compromise are distinguished from the external GCS checkpoint.

**Read permissions on other Tasks' tables:** SELECT is granted only to the roles below. Cross-reads not listed in the table are not created.

| DB role | SELECT targets |
| --- | --- |
| `gateway_reader`(TASK-04) | `sessions`, `session_tokens`, `service_sessions`, `issued_certificates`, `approvals`, `activation_probes` (`action_id` is filled only through `bind_activation_probe_action()` below), `active_policy`, `desired_bundle`, `holds`, `control_health_leases`, `workload_data_state`, `action_results`, `adapter_executions`, `attempts`, `reservations` |
| `coordinator_reader`(TASK-03) | `holds`, `control_health_leases`, `node_boot_generation`, `decisions`, `desired_bundle` |
| `identity_app`(TASK-03) | `desired_bundle`, `intent_checks`, views `pending_approval_actions`, `action_content_previews`, and `approval_contract_actions` (`action_id, session_id, tenant, environment, operation_id, target_id, canonical_target, disclosure_fields, content_digest` and the latest decision's `verdict`, for rendering approval contracts), `active_policy` |
| `adapter_reader`(TASK-05) | `decisions`, views `adapter_action_envelopes` and `adapter_action_contents` (only rows for its own adapter_id), `desired_bundle`. It does not read the `actions` and `action_contents` tables directly |
| `correlation_reader`(TASK-10) | `attempt_observations`, `kernel_events`, `lifecycle_events` |
| `start_coordinator`(TASK-10) | `kernel_events` (bypass detection), `lifecycle_events` |
| `control_health_writer`(TASK-10) | `desired_bundle` (to compute `bundle_ack`), `active_policy`, `identity.work_readiness_session_view`, `correlation.lifecycle_intervals` for judging its own node/Pod |
| `evidence_collector`(TASK-08) | `actions_target_view`, view `audit.collector_feed` (TASK-07, includes the `tenant` column; the collector queries only rows of its own tenant) |
| `timeline_reader`(TASK-11) | Tenant-filtered views of audit, results, correlation, and receiver effects, `issue_evidence`, `correlation.network_findings` and the view `correlation.network_findings_latest` (read filtered by the action's `workload_id`) |
| `proposer_reader`(TASK-12) | `decisions`, `decision_inputs`, `action_results`, `active_policy`, `fixture_registry`, `issue_evidence` |
| `broker_reader`(TASK-06) | Only `coordinator` schema USAGE and `attempt_credential_scope` SELECT. SELECT on `identity.registered_workloads` and on the original attempts, reservations, and actions is not granted. This is the only DB role name used for the broker |
| `audit_exporter`(TASK-07) | `decisions.decision_inputs` (for the `gcs_decision_inputs` export) |

**coordinator health row lock:** The cross-table privileges of `coordinator_reader` stay as in the SELECT table above. The reader is not given the UPDATE privilege that PostgreSQL requires for `SELECT ... FOR SHARE`; instead it calls the two `SECURITY DEFINER` functions below, owned by TASK-10. The function owner is `health_owner`, `search_path` is pinned to `pg_catalog, health, pg_temp`, and every table is referenced by its schema-qualified name. PUBLIC EXECUTE is revoked and EXECUTE is granted only to `coordinator_reader`. Neither function modifies rows.

- `health.lock_dispatch_holds(p_node_uid uuid, p_workload_id text, p_target_id text, p_session_id uuid, p_service_session_id uuid) RETURNS TABLE(hold_id uuid, reason text)`: locks with `FOR SHARE`, in `hold_id` order, the holds with `released_at IS NULL` that are `global/*` or exactly match the passed node, workload, target, or session scope. Global is always included. Optional arguments not used on a given path are NULL, and an empty text is rejected. Both session arguments correspond to the existing `session` scope. The function does not accept SQL strings or arbitrary scope conditions as arguments.
- `health.lock_dispatch_node(p_node_uid uuid) RETURNS TABLE(boot_id text, sensor_generation bigint, guard_generation bigint, state text)`: locks with `FOR SHARE`, in `boot_id` order, the rows with `state <> 'retired'` for a non-NULL node UID. The coordinator checks that the result is exactly one row and that it matches the boot and lease generation of the adapter certificate. Zero rows or multiple rows are not treated as ready and are handled through the existing failure path.

The caller invokes the holds function and then the node function, following the existing lock order, in the **same DB transaction** as the reservation and permit check. The locks are held until the end of the transaction even after the functions return. The `SET LOCAL lock_timeout = '2s'` setting and the rule of a full rollback/503 `LOCK_TIMEOUT` on timeout remain unchanged. `FOR SHARE` on existing rows does not block new hold INSERTs, so the existing rule of re-querying in the permit check is also kept. No additional row lock is taken for the lease lookup.

**Adapter audit path:** The TASK-05 adapters call `audit_append()` directly through `adapter_app` (NOLOGIN, member of `adapter_reader` and `audit_producer`). The HTTP call `POST /internal/audit/events` is not a required path for adapters. Per-event append and business state updates are separate transactions, and conflict handling during internal replay follows [TASK-07 3.1](TASK-07-audit-store.md). The existing audit-writer allowed path and caller-map in TASK-06 are an upper bound on network permissions, not a requirement to replace direct DB calls with HTTP calls.

**Audit write privileges:** Producer DB roles are members of the role `audit_producer`, and only this role has EXECUTE on the SECURITY DEFINER function `audit_append()`. Table INSERT and SELECT privileges are not granted. In PostgreSQL every form of `ON CONFLICT` requires SELECT privilege on the conflict target columns ([PostgreSQL INSERT](https://www.postgresql.org/docs/17/sql-insert.html)), so duplicate detection is done inside the function. The function pins `search_path`, looks up `session_user` in `db_role_sources(db_role, source_id)`, and rejects the event if it differs from the event's `source_id` (impersonation prevention). The return value is `created | duplicate | conflict`; for a business append, the conflict record is written by `audit_record_conflict()` in a separate transaction after the business rollback. For a digest conflict on the same source and record ID within a kernel/lifecycle partial batch, this function is called inside the ingest transaction and committed atomically with the normal records, outbox, and watermark (TASK-07 §3.3). `audit_exporter`'s UPDATE on `audit_outbox` is restricted to the columns `(state, attempts, lease_until, next_retry_at, ack_ref)`. The writer has no UPDATE/DELETE, DB owner, or schema DDL privileges. The `received_at` response of the audit API is looked up only through `audit.audit_event_ack(event_id, source_id, tenant)`. Only `audit_writer` executes this function, and base table SELECT is not granted. The writer passes only the source and tenant whose mTLS and producer registration it has verified, performs the append and ack lookup in the same transaction, and responds after COMMIT succeeds. A duplicate response returns the original storage time unchanged.

**Registration of DB functions, views, and identifiers:** DB objects called by multiple Tasks, and certificate, header, and label identifiers, are created only under the names below. EXECUTE on a function is granted only to the roles in the "Caller" column (`revoke_approvals_for_policy_change` → `releaser_app` (TASK-14), `resolve_unknown_attempt` → `timeline_app` (TASK-11), `bind_activation_probe_action` → `gateway_app`, `audit_append` and `audit_record_conflict` → `audit_producer`, `audit.audit_event_ack` → `audit_writer`, `audit.enqueue_decision_input` → `gateway_app`). The DB roles of identity, coordinator, gateway, adapter, releaser, and timeline are all members of `audit_producer`. `health_owner` (NOLOGIN), the owning role of `health.record_drift`, is also a member so that it can call `audit_append` inside the function, and this membership is granted by the TASK-07 migration. The caller `drift_reporter` is not a member.

| Object | Owner | Caller | contract |
| --- | --- | --- | --- |
| `health.lock_dispatch_holds(uuid, text, text, uuid, uuid)` | TASK-10 | `coordinator_reader` | Looks up and locks open holds under the health row lock rule above. UPDATE is not granted to the reader |
| `health.lock_dispatch_node(uuid)` | TASK-10 | `coordinator_reader` | Looks up and locks the current node boot under the health row lock rule above |
| `audit_append(event, outbox_destinations)` | TASK-07 | `audit_producer` members | SECURITY DEFINER. Returns `created`/`duplicate`/`conflict`. These two are its only arguments |
| `audit_record_conflict(record_kind, record_id, rejected_digest, source_id)` | TASK-07 | `audit_producer` members | Records only a different digest for the same source and an existing record ID: for a business append in a separate transaction after the business rollback, and for a kernel/lifecycle partial batch inside the ingest transaction. On failure the whole transaction rolls back. Returns `conflict_id` |
| `audit.audit_event_ack(event_id, source_id, tenant)` | TASK-07 | `audit_writer` only | SECURITY DEFINER. Returns `timestamptz`. After checking the proxy registration of `session_user` and its `audit_writer` membership, it returns only the `received_at` of the stored row that matches all three arguments. If none exists or the scope differs, it rejects with a permission error and does not expose the payload |
| `identity.audit_source_certificate(certificate_serial, exact_san, requested_boot_hash DEFAULT NULL)` | TASK-03 | `audit_writer`, `audit_owner`, `correlation_writer` (TASK-10 netpol linker, TASK-10 migration) | Restricted cert/node/boot lookup. Return and historical evidence rules are in [Lifecycle source](#lifecycle-source-authentication-and-epoch) |
| `health.audit_source_current_boot(node_uid, certificate_boot_id)` | TASK-10 | `audit_writer`, `audit_owner` | Returns as a boolean whether a non-retired current boot matches, only for the lifecycle runtime and kernel sources. Not applied to the watcher |
| `audit.probe_evidence_events(node_uid, boot_id, container_ids, from_time, to_time)` | TASK-07 | `control_health_writer` | Looks up the basis for an answer probe pass. Returns only the process, tcp, and file events of the specified containers on the same node and boot, plus fixed columns of `tcp_state` rows whose tuple matches those connects; table SELECT is not granted ([TASK-10 3.2](TASK-10-correlation-health.md#32-control-health-decision)) |
| `release.active_sensor_baseline()` | TASK-14 | `drift_reporter` only | SECURITY DEFINER. `RETURNS TABLE(epoch bigint, change_id uuid, sensor_release_policies_digest char(64))`, where `change_id` is the current `active_policy.activated_by_change_id`. There is at most one row. Table SELECT is not granted |
| `health.record_drift(drift_observation_id, baseline_kind, scope, scope_id, expected_digest, observed_digest, observation, source_time, proposed_hold_id, drift_event, hold_requested_event, execution_held_event)` | TASK-10 | `drift_reporter` only | SECURITY DEFINER (`health_owner`). Commits the drift observation, the `control_drift_detected`, `hold_requested`, and `execution_held` audit events, and the `control_drift` hold in one transaction. Accepts only the `global`/`*` scope. `observation = unjudgeable` (consecutive read failures) also requests a hold. It does not release holds or change leases or nodes. The contract is in [TASK-10 3.2](TASK-10-correlation-health.md#32-control-health-decision) |
| `audit.ingest_lifecycle_batch(source_id, batch, certificate_serial, exact_san, writer_version, writer_epoch)` | TASK-07 | `audit_writer` only | SECURITY DEFINER. Verifies source/cert/epoch and stores in the same transaction. Responds with JSON |
| `audit.ingest_kernel_batch(source_id, batch, certificate_serial, exact_san, writer_version, writer_epoch)` | TASK-07 | `audit_writer` only | SECURITY DEFINER. [Kernel source authentication and epoch](#kernel-source-authentication-and-epoch). Verifies source/cert/current boot/epoch and stores in the same transaction. Responds with JSON |
| `audit.lifecycle_checkpoint(source_id, scope)` | TASK-07 | `audit_writer` only | SECURITY DEFINER. Returns only scope, resource_version, committed_at, and checkpoint_revision for one source/scope. [checkpoint CAS](#lifecycle-checkpoint-revision-cas) |
| `audit.enqueue_decision_input(decision_input_digest, record_bytes)` | TASK-07 | TASK-04 decision transaction | Adds an outbox row with `record_kind = decision_input` and destination `gcs_decision_inputs` |
| `audit.acquire_manifest_lease(chain_id, holder)`, `audit.release_manifest_lease(chain_id, holder, fencing_token)` | TASK-07 | `audit_exporter` only | SECURITY DEFINER. 30-second PostgreSQL lease and fencing token for the manifest writer. On intent and manifest INSERT, a trigger checks the current token ([TASK-07 3.2.1](TASK-07-audit-store.md#321-confirmed-export-items)) |
| `audit.purge_expired_records(batch_limit)` | TASK-07 | `audit_retention` only | SECURITY DEFINER. Deletes only the source, outbox, and member rows of batches that are fully acked, whose source records are 30 days old, and whose manifest commit (`export_manifests.created_at`) is 31 days old. This does not overlap the verification window (30 days from manifest commit) |
| `revoke_approvals_for_policy_change(new_epoch, patch_kind, allowed_fields)` | TASK-03 | TASK-14 activation transaction | Applies the [policy change and approval invalidation](#policy-changes-and-approval-invalidation) table; `approval_revoked` for each revocation |
| `resolve_unknown_attempt(attempt_id, resolution_id)` | TASK-03 | TASK-11 resolutions transaction (the only call path) | `unknown → resolved` transition, `unknown_resolved` event |
| view `attempt_credential_scope(attempt_id, adapter_id, operation_id, state, adapter_namespace, adapter_ksa)` | TASK-03 | TASK-06 broker (SELECT only; requires USAGE on the `coordinator` schema) | Basis for the `credentials:resolve` check. Inside the view, `registered_workloads.enabled = true`, `role = adapter`, and a matching `adapter_id` with the attempt are checked. The broker compares the ns/sa of the verified caller SAN against the two adapter columns. There is one row per `(attempt_id, adapter_namespace, adapter_ksa)`, and registration deactivation and role or adapter changes are reflected on the next lookup |
| `bind_activation_probe_action(service_session_id, client_request_key, action_id)` | TASK-03 | TASK-04 decision transaction | SECURITY DEFINER. Fills `action_id` on the registered row only when it is null, and fails if it already has a different value |
| view `pending_approval_actions(action_id, session_id, operation_id, decision_id, created_at)` | TASK-04 | TASK-03 identity service (SELECT only) | Basis for `GET /v1/approvals/pending` |
| view `action_content_previews(content_digest, preview_text, truncated)` | TASK-04 | TASK-03 contract renderer (SELECT only) | Preview of content whose action `data_class` is `none` or `synthetic`. One row per `content_digest` (`DISTINCT`, because content bytes are identical even when several action rows share the digest). Adapters read raw content only through the `adapter_action_contents` view |
| view `actions_target_view(action_id, tenant, operation_id, canonical_target)` | TASK-04 | TASK-08 `evidence_collector` (SELECT only) | Receipt target check |
| view `adapter_action_envelopes(action_id, envelope)` | TASK-04 | TASK-05 `adapter_reader` (SELECT only) | Only the action envelopes of the connected adapter among actions that received an allow decision. The adapter is identified by `adapter_db_roles` below and `session_user` |
| view `adapter_action_contents(content_digest, tenant, action_id, adapter_id, content_bytes, created_at, expires_at)` | TASK-04 | TASK-05 `adapter_reader` (SELECT only) | Only unexpired content of the actions above. Only rows for the connected adapter's `adapter_id` are visible |
| table `adapter_db_roles(db_role PK, adapter_id)` | TASK-04 (schema), TASK-16 (registers rows at installation) | The two views above (read with owner privileges) | Maps the Cloud SQL IAM DB user name of an adapter KSA to `adapter_id`. An unregistered login sees no rows in the views. A login is not shared by multiple adapters. `adapter_reader` and PUBLIC have no privileges |
| header `X-Agentarium-Peer-Identity` | TASK-03 | gateway (sets), identity service, control-health, audit-writer (verify) | When the gateway forwards execution-plane paths (`/internal/workload-certificates`, `/v1/runtime/assignments`, `/v1/sessions/{session_id}:claim`, `/v1/sessions/{session_id}:refresh` to the identity service; `/v1/runtime/session-workers*`, `/v1/runtime/work-readiness/checks*`, `/v1/runtime/probe-reports` to control-health; `/v1/runtime/work-events` to audit-writer), it strips any header of the same name sent by the client and inserts the verified SAN. The receiving service trusts only values arriving on an mTLS connection from the exact installed gateway SAN |
| header `X-Agentarium-Peer-Certificate-Serial` | TASK-04 | gateway (sets), control-health (verifies) | When the gateway forwards `/v1/runtime/probe-reports` to control-health, it strips any header of the same name sent by the client and inserts the serial of the verified client leaf. The format is the same hex normalization as `serial` in the issuance API response. control-health uses only values arriving on an mTLS connection whose TLS peer is the gateway SAN (`spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway`), and it must receive the value together with the SAN in `X-Agentarium-Peer-Identity` |
| header `X-Agentarium-Peer-Session` | TASK-04 | gateway (sets), control-health (verifies) | When the gateway forwards `/v1/runtime/session-workers*` and `/v1/runtime/work-readiness/checks*` to control-health, it strips any header of the same name sent by the client and inserts the `session_id` verified with the session token. The body is not rewritten. control-health uses only values arriving on a gateway SAN mTLS connection, compares the value with the `session_id` of the target worker or check on registration, lookup, and close, and rejects with 403 if they differ |
| header `X-Agentarium-Console-Actor`, `X-Agentarium-Console-Roles` | TASK-03 | identity console BFF (sets), target service (verifies) | Inserted by the BFF on [console paths](#console-path-and-idp). The target service trusts only values arriving on a connection from the identity service SAN |
| header `X-Agentarium-Service-Session` | TASK-05 | evidence-reader adapter (sets), TASK-11 timeline and TASK-02 discovery (verify) | The value is the `service_session_id` of the service session that submitted the `evidence.*` or `discovery.*` read. The gateway strips any header of the same name sent by the client on `POST /v1/actions` requests and does not use it for decisions or storage. The gateway stores in GatewayDecision the `service_session_id` verified with the service session token. evidence-reader builds this header directly from the `service_session_id` of the stored decision. timeline and discovery use only values arriving on an mTLS connection whose TLS peer's client URI SAN is exactly `spiffe://agentarium.internal/ns/agent-adapters/sa/evidence-reader`. If a header with this name appears in ClientAction arguments or action content, it is rejected (the gateway with 422 `SCHEMA_INVALID`, adapter Prepare with 409 `PREFLIGHT_MISMATCH`) |
| Certificate SAN | TASK-03 | All mTLS servers | [Service PKI](#service-pki-and-identifiers) |
| Service actor `service:<namespace>/<ksa>` | TASK-03 | gateway, audit | The `authenticated_actor` of a service session. It does not overlap with user actors (`google:<sub>`) |
| label, KSA | TASK-01, 06 | NetworkPolicy, Admission | [KSA and label rules](#service-pki-and-identifiers) |

### Lock order and time

- Global lock order: `active_policy → holds → node_boot_generation → sessions → service_sessions → issue_candidates → service_session_counters·session_budgets → issue_candidate_counters → approvals → reservations → attempts → dispatch_permits → session_process_bindings → work_readiness_checks`. A readiness transaction checks only the required rows of the earlier stages in this order and locks its own check last. No lock is held while waiting for a node response. No transaction may violate this order. A transaction that starts from a row of a later stage (outcome report, sweeper) does not lock first; it reads only the IDs, then locks in this order and verifies again.
- `active_policy` is locked with `FOR SHARE` in reservations and with `FOR UPDATE` only in policy activation.
- Expiry comparisons use `statement_timestamp()`. `CURRENT_TIMESTAMP` (the transaction start time) is not used for expiry comparisons.
- The row lock timeout is 2 seconds; when exceeded, 503 `LOCK_TIMEOUT` is returned.

### Reservation transaction

```text
BEGIN  -- READ COMMITTED
  SELECT active_policy FOR SHARE
  SELECT * FROM health.lock_dispatch_holds(adapter_node_uid, workload_id, target_id, session_id, service_session_id)
    if any hold:
      allow only if every matching hold has reason = policy_activation
        and decision.decision_basis = activation_probe
        and activation_probes(activation_probe_id).target_epoch = active epoch
      else reject HOLD_ACTIVE
  SELECT * FROM health.lock_dispatch_node(adapter_node_uid) -- exactly one row, verify boot and generation
  SELECT sessions | service_sessions FOR UPDATE
  SELECT service_session_counters FOR UPDATE -- service session path only (profile budget)
  SELECT session_budgets FOR UPDATE          -- standing rule path only
  SELECT issue_candidate_counters FOR UPDATE -- only service sessions that have a candidate (issue_id, candidate_id)
  SELECT approvals FOR UPDATE                -- approval path only
  verify decision: verdict = allow, expires_at > statement_timestamp(),
         policy_epoch = active epoch, catalog_digest = active, opa_bundle_revision = expected,
         control_health lease valid, owner/revocation
  INSERT reservations (action_id UNIQUE) ON CONFLICT DO NOTHING
    if existed and state = reserved|committed: verify same action_digest and retry eligibility (no second budget deduction)
    if existed and state = released: reserve again and consume budget again (released means the budget was returned)
    if new: UPDATE approvals SET used_actions = used_actions + 1 ... (or session_budgets / service_session_counters)
            -- if there is a candidate, +1 both rows together only when issue_candidate_counters.used_value < that session's max_value
  INSERT attempts (state = planned)          -- unique violation if an active/unknown attempt exists
  INSERT dispatch_permits (expires_at = statement_timestamp() + 10s)
  SELECT audit_append(attempt_planned, outbox)
COMMIT
return DispatchPermit
```

The permit's `claimed_at` is updated only once, from null to `statement_timestamp()`, in the final check transaction, and in the same transaction the reservation is changed to `committed` and the attempt to `claimed`. A duplicate check or an expiry/revocation/epoch/health mismatch does not grant dispatch authority.

**released handling (outcome API and sweeper):**

```text
-- 1. Read attempt_id → reservation_id, approval_id | session_id without locking
BEGIN
  SELECT sessions | service_sessions FOR UPDATE
  SELECT service_session_counters FOR UPDATE | SELECT session_budgets FOR UPDATE
  SELECT issue_candidate_counters FOR UPDATE -- only service sessions that have a candidate
  SELECT approvals FOR UPDATE                -- approval path only
  SELECT reservations FOR UPDATE
  SELECT attempts FOR UPDATE ; re-verify state = planned (before claim)
  SELECT dispatch_permits FOR UPDATE ; re-verify claimed_at IS NULL
  UPDATE attempts SET state = released
  UPDATE reservations SET state = released
  UPDATE approvals SET used_actions = used_actions - 1 | session_budgets ... | service_session_counters ...
  UPDATE issue_candidate_counters SET used_value = used_value - 1 -- if there is a candidate. The same candidate row even if the session expired and a new session exists
  SELECT audit_append(attempt_released, outbox)
COMMIT
```

**coordinator sweeper:** Runs every 5 seconds. A `planned` attempt whose permit expired without being claimed is changed to `released` by the procedure above (budget restored, `released_by = sweeper`). A `claimed` or `dispatched` attempt with no outcome report within 60 seconds after claim is changed to `unknown` (`OUTCOME_TIMEOUT`, `attempt_uncertain`). The sweeper reports the `coordinator` component lease.

**Adapter commit order:** When the adapter receives a response, it (1) raises `workload_data_state` with `GREATEST` (idempotent), (2) reports the attempt state through the outcome API, (3) writes `action_results`, and then (4) changes `adapter_executions.state = completed`. On restart, rows in `adapter_executions` that are not `completed` are re-run in this order. Because the class is raised first, a subsequent disclosure request is not decided at a lower class even if a crash occurs midway.

### Failure classification

| Point | Examples | attempt | reservation and budget | Retry |
| --- | --- | --- | --- | --- |
| Before permit claim | `CREDENTIAL_UNAVAILABLE`, permit denied, hold, permit expired (sweeper) | `released` | `released`, budget restored | Can be resubmitted with a new decision |
| After claim, before `WroteHeaders` | connect or TLS failure, header write failure | `failed` | Kept, budget not restored | MVP automatic retries 0. Manual resubmission only |
| No response after `httptrace` `WroteHeaders`, no outcome within 60 seconds after claim | timeout, crash | `unknown` | Kept | Automatic retries prohibited. Resumes only after the `unknown_resolved` transition |

The table mapping per-adapter HTTP status, `finishReason`, and `promptFeedback.blockReason` → `(attempt.state, execution_state, reason_codes)` is owned by TASK-05. Even before `WroteHeaders`, some header bytes may have gone out to the socket. This contract assumes the target does not process an incomplete request and classifies it as `failed`, and it reports this assumption as a limitation. A receiver retry is performed with a new attempt and a new permit under the same reservation only when receiver dedupe has been verified. Because the active partial unique index includes `unknown`, a new attempt cannot be created until an `unknown → resolved` transition is recorded through the operator API (`POST /v1/actions/{action_id}/resolutions`).

### execution_state derivation

`GET /v1/actions/{action_id}` and `/result` (TASK-04) use the first matching row in the order below. The timeline (TASK-11) adds target evidence to the same rules. attempt `resolved` shows the resolution result from TASK-11.

| Condition | execution_state |
| --- | --- |
| Latest decision `deny` | `denied` |
| Latest decision `approval_required` and no usable approval | `approval_pending` |
| `adapter_executions.state = preflight_rejected` | `preflight_rejected` |
| `allow` and no attempt | `dispatch_pending` (the response also carries `execute_requests.state` as `dispatch_status`) |
| Latest attempt `planned` or `claimed` | `attempt_planned` |
| Latest attempt `dispatched` | `dispatched` |
| Latest attempt `response_received` | `action_results.execution_state` (`accepted` or `failed`). `effect_verified` and `effect_mismatch` require target evidence, so only the TASK-11 timeline computes them, and this API points to them with `alignment_ref` |
| Latest attempt `failed` or `released` | `failed` |
| Latest attempt `unknown` | `unknown` |

### Activation probe-only dispatch

During a `policy_activation` hold, only activation probe actions registered by the releaser (TASK-14) can receive a permit. Registration happens before submission.

1. The TASK-14 releaser creates a service session (`activation_probe` profile, `change_id` scope).
2. The releaser registers `{change_id, client_request_key, target_epoch}` with `POST /internal/dispatch/activation-probes` (TASK-03). At this point there is no `action_id`.
3. The releaser submits `POST /v1/actions` with the same `client_request_key`. The gateway finds the registration row by `(service_session_id, client_request_key)`, fills in `action_id` in the decision transaction, and passes it to Rego as `control_health.activation_probe`.
4. Rego decides with `probe.activation.v1` (fixed probe target, disclosure fields `[summary]`, 4 times per service session) and `hold.activation_probe_exempt.v1`. The probe is also subject to the normal deny rules. If there is no registration row, the result is `HOLD_ACTIVE`; after registering, resubmit or call `:reevaluate`. `:reevaluate` can also be used after a deny.
5. The TASK-03 coordinator lets the probe through only in the hold branch of the reservation transaction above. If there is any other hold reason, the probe is also rejected.
6. **Probe expected values:** The expected outcome is derived from the bundle being activated. Activation uses `expected_by_role.candidate` of the same fixture in the `candidate_final` report of that change, and rollback uses `expected_by_role.baseline`. Fixed expected values are not used. `reason_codes` are compared by the subset comparison (expected ⊆ actual) of the [Outcome](#policy-improvement-testing-and-discovery) comparison rules.

### Policy changes and approval invalidation

An approval records the `policy_epoch` at the time of approval. When a new epoch becomes active, the following rules apply per patch type. In all cases, if the decision's epoch differs from the active epoch, the reservation is rejected with `POLICY_EPOCH_STALE`, and the runtime or console obtains a new decision with `:reevaluate`.

| Patch type | Handling of unused approvals | Notes |
| --- | --- | --- |
| Narrowing `receiver.allowed_disclosure_fields` | Unused approvals whose `disclosure_fields` are not a subset of the new allowed set are changed to `revoked(revoke_reason = policy_changed)` | Handled in the same activation transaction, `approval_revoked` event |
| Widening the disclosure scope, other `receiver.*` | Kept, re-decided at the next reservation | Widening does not broaden the scope of existing approvals |
| `targets` | Kept, re-decided at the next reservation | A removed target yields `TARGET_SCOPE_DENIED` |
| `standing_rules` | Not applicable (no approval), re-decided at the next reservation | `session_budgets` is kept |
| `adapter_constraints`, catalog changes | Kept, re-decided at the next reservation | A `catalog_digest` mismatch yields `CATALOG_DIGEST_MISMATCH` |
| `policy.draft.create` | Kept, re-decided at the next reservation | Because it only narrows, it does not broaden the scope of existing approvals |
| `sensor_rules` | No effect | The sensor generation changes, so unconsumed start permits are discarded |

## Internal API responsibilities

| API path | Owning Task | Allowed caller | Responsibility |
| --- | --- | --- | --- |
| `POST /v1/sessions` | TASK-03 | Authenticated user (console) | Creates a session with `workload_id`, `task_statement`, and scope, and issues a `claim_code` |
| `GET /v1/runtime/assignments` | TASK-03 | runtime (workload mTLS) | List of sessions assigned to the workload. No token is given |
| `POST /v1/sessions/{session_id}:claim` | TASK-03 | runtime (mTLS + claim_code) | Issues a session token bound to the workload identity |
| `POST /v1/sessions/{session_id}:revoke` | TASK-03 | Console owner, operator | Revokes the session (cancels unused approvals with `session_ended`) and invalidates the token |
| `POST /internal/sessions:revoke-scope` | TASK-03 | TASK-10 control-health | Revokes active sessions within the `operator_stop` hold scope (cancels unused approvals with `session_ended`) and invalidates the tokens |
| `POST /v1/sessions/{session_id}:refresh` | TASK-03 | runtime (mTLS + current token) | Reissues the token before `expires_at`. The maximum lifetime is 8 hours after creation |
| `POST /internal/service-sessions` | TASK-03 | Registered service principals: TASK-12 proposal service, TASK-04 intent checker, TASK-02 discovery analyzer, TASK-14 releaser | Service session scoped by profile, issue/candidate/change/snapshot/action, tenant, `tool_budget`, and TTL |
| `POST /internal/workload-certificates` | TASK-03 | All KSAs registered in `registered_workloads` (runtime, probe runner, start fixture, node runtime bridge, and hostNetwork agent-sensors service workloads (`tetragon` exporter, `netpol-collector`) go through the gateway; other services call directly) | Issues an mTLS certificate after comparing TokenReview → Pod `spec.nodeName` → Node `status.nodeInfo.bootID`. Trust limit: bootID is self-reported by the kubelet |
| `POST /v1/actions` | TASK-04 | runtime session token, service session | Normalization, decision, and single-transaction storage; if `allow`, calls the adapter via `execute_requests` and returns 202 |
| `GET /v1/actions/{action_id}` | TASK-04 | Owner, the corresponding service session | Queries the decision and execution_state |
| `GET /v1/actions/{action_id}/result` | TASK-04 (data from TASK-05) | Owner, the corresponding service session | Sanitized result, data_class, truncation, evidence_level |
| `POST /v1/actions/{action_id}:reevaluate` | TASK-04 | runtime, console (via the identity BFF) | New decision_id and a new 10-second TTL with the same action_id and action_digest |
| `GET /v1/approvals/pending?session_id=` | TASK-03 | Console owner | List of pending approvals |
| `GET /v1/actions/{action_id}/approval-contract` | TASK-03 (the intent check call is TASK-04) | Console owner | Server-rendered display contract, `displayed_contract_digest`, intent check warnings |
| `POST /internal/intent-checks` | TASK-04 | TASK-03 contract renderer, gateway (standing rule path) | Creates and stores an IntentCheckResult. The contract rendered by TASK-03 is passed as `rendered_contract`, and the intent checker does not rebuild the contract |
| `POST /v1/approvals` | TASK-03 | Console owner | Creates an approval and checks acknowledgements |
| `POST /v1/approvals/{approval_id}/revoke` | TASK-03 | Owner, operations cancel role | Cancellation |
| `POST /internal/adapter/{adapter_id}/execute` | TASK-05 | gateway | Re-checks the stored values and then starts execution |
| `POST /internal/dispatch/reservations` | TASK-03 | adapter | Reservation transaction |
| `POST /internal/dispatch/permits/{permit_id}/check` | TASK-03 | The same adapter | Claim and final recheck |
| `POST /internal/dispatch/attempts/{attempt_id}/outcome` | TASK-03 | The same adapter | Transitions to `dispatched`, `response_received`, `failed`, `unknown`, `released` and audit events |
| `POST /internal/dispatch/activation-probes` | TASK-03 | TASK-14 releaser | Registers the probe with `client_request_key` before submission |
| `POST /internal/credentials:resolve` | TASK-06 | adapter (after reservation, before permit claim) | Provides the credential after comparing `attempt_id, adapter_id, credential_binding` against `attempt_credential_scope`. On failure, the adapter reports attempt `released`. The model adapter's Google token is obtained directly from the GKE metadata server (WIF), not from this API (TASK-05, 06) |
| `POST /internal/audit/events` | TASK-07 | Registered producer | `audit_append()`, source identity check |
| `POST /internal/kernel/events:batch` | TASK-07 (receive, ack), TASK-10 (correlation consumption) | TASK-09 exporter | Checksum and metadata check; on receiving `sequence_range_abandoned`, stores an ObservationGap and then moves the watermark |
| `POST /internal/lifecycle/events:batch` | TASK-07 (receive, ack), TASK-10 (consumption) | TASK-09 lifecycle recorder, Pod watcher | Appends raw facts, removes duplicates, updates the watch cursor |
| `GET /internal/lifecycle/checkpoints?scope=` | TASK-07 | TASK-09 Pod watcher | Queries the last COMMITted watch cursor |
| `POST /internal/control-health/leases` | TASK-10 | TASK-03/04/05/07/08/09/14, node-readiness, network policy log node collector (`component = netpol-collector`) | Combined report of heartbeat and active version ack |
| `POST /internal/network-policy/records:batch` | TASK-10 | Network policy log node collector (TASK-06 3.4) | Receives NetworkPolicyRecords, removes duplicates, ack watermark. The method is the same as the kernel batch |
| `POST /internal/control-health/observation-gaps` | TASK-10 | TASK-09 pod-watcher (exact SAN `spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher`) and runtime lifecycle recorder (`.../agent-sensors/sa/lifecycle-recorder`, node certificate) | Durable record of lifecycle gaps without an assigned sequence (`lifecycle_capture`/`WATCH_HISTORY_EXPIRED`, `RUNTIME_RECORD_MISSING`). The format is in [TASK-10 3.6 watch history gap reception](TASK-10-correlation-health.md#section-ref) |
| `POST /internal/control-health/probe-results` | TASK-10 | TASK-07 audit-exporter, TASK-08 evidence-collector, TASK-09 sensor exporter, TASK-10 probe runner (via the gateway relay) | Submits probe results. They become the basis for automatic release (`probe_result_ids`) |
| `POST /v1/runtime/session-workers`, `GET /v1/runtime/session-workers/{id}`, `POST /v1/runtime/session-workers/{id}:close` | TASK-04 (relay), owner TASK-10 | Workload mTLS of the trusted supervisor + claimed session token | Registration, independent observation state, closing of new-work permission. {id} is worker_binding_id |
| `POST /internal/control-health/session-workers`, `GET /internal/control-health/session-workers/{id}`, `POST /internal/control-health/session-workers/{id}:close` | TASK-10 | gateway relay only | Verifies caller/session/epoch and the registration digest. Self-authentication of observation through the worker token or arbitrary argv is forbidden |
| `POST /internal/control-health/worker-observation-results` | TASK-10 | TASK-09 registered node-sensors, own node/boot only | Independent report of nonce, live process identity, kernel exec COMMIT reference, and generation |
| `POST /v1/runtime/work-readiness/checks`, `GET /v1/runtime/work-readiness/checks/{id}` | TASK-04 (relay), owner TASK-10 | Workload mTLS of the runtime + claimed session token | Creates a pending check and queries its own result. Required before running work even after the token claim |
| `POST /internal/control-health/work-readiness/checks`, `GET /internal/control-health/work-readiness/checks/{id}` | TASK-10 | gateway relay only | Passes the verified caller/session, confirms the actual instance and nonce, and makes a durable decision |
| `POST /internal/control-health/pod-observation-results` | TASK-10 | TASK-09 node-sensors, own node/boot only | Reports nonce, check ID, actual container/cgroup, generation, and WAL/filter state |
| `POST /v1/runtime/work-events` | TASK-04 (relay), owner TASK-07 | Workload mTLS of the runtime + claimed session token | agent_work_* only, with caller/session/check linkage confirmed. It cannot self-issue a readiness pass |
| `POST /internal/audit/work-events` | TASK-07 | gateway relay only (the exact gateway SAN fixed at installation) | Receives the runtime SAN verified by the gateway (`X-Agentarium-Peer-Identity`), the session context, the WorkReadinessCheck, and the runtime event, builds the AuditEvent directly, and stores it with `audit_append()` |
| `POST /v1/runtime/probe-reports` | TASK-04 (relay), data owner TASK-10 | Probe runner in `agent-exec` (workload mTLS) | The gateway attaches the caller SAN as `X-Agentarium-Peer-Identity` and the leaf serial as `X-Agentarium-Peer-Certificate-Serial`, and forwards to `POST /internal/control-health/probe-results`. The lease is also reported through the same relay |
| `POST /internal/holds` | TASK-10 | Registered components (TASK-07/09/11/14, etc.). `reason = operator_stop` only from the console BFF (operators with the operator role). The probe runner does not call it. For TASK-10 probe results, the requester and owner is `control-health`, which verified the result, and the TASK-08 destination probe is requested and owned by `destination-evidence` | Hold request. TASK-10 decides |
| `POST /internal/holds/{hold_id}/release` | TASK-10 | The owning component of the reason; operator approval for security reasons | Hold release |
| `GET /internal/holds?owner_component=` | TASK-10 | Owning components with automatic release permission (TASK-07 `audit-export`, etc.). Own component only | List of unreleased holds it owns. A query used to continue probe-based release after a restart |
| `GET /internal/control-health?scope=&scope_id=` | TASK-10 | coordinator, gateway, releaser, verification services, node-readiness, node-sensors and node runtime bridge (own node/boot only) | Summary of leases, holds, and gaps. The response schema is in TASK-10 chapter 4 |
| `POST /internal/runtime/start-permits` | TASK-10 | node runtime bridge | Only on nodes with `startup_guard_gate` enabled |
| `POST /internal/runtime/start-permits/{id}/consume` | TASK-10 | The same bridge | Single consumption |
| `GET /internal/runtime/start-attempts/{id}` | TASK-10 | Bridge on the same node/boot, operations investigation role | State query. Not a restart permission |
| `POST /internal/runtime/start-attempts/{id}/transitions` | TASK-10 | Bridge on the same node/boot | CAS of allowed transitions |
| `POST /test/v1/submissions` | TASK-08 | receiver-sender adapter | Records the independent digest and effect |
| `GET /test/v1/receipts/{action_id}` | TASK-08 | TASK-08 evidence collector only | Receipt query. The adapter does not call it |
| `GET /internal/evidence/actions/{action_id}`, `/bundles/{bundle_id}`, `/regressions/{run_id}` | TASK-11 `services/timeline` | evidence-reader adapter | Sanitized evidence, issue/tenant scope |
| `GET /v1/actions/{action_id}/timeline` | TASK-11 | Owner, operations query role | [Timeline response schema](#timeline-response-schema) |
| `POST /v1/actions/{action_id}/resolutions` | TASK-11 | Operator (evidence reference required) | `unknown_resolved`; on mismatch, requests a session hold |
| `POST /internal/issues` | TASK-12 | TASK-11 verifier, TASK-04 intent checker (`source = intent_divergence`), TASK-10 correlation (`source = network_finding`) | Issue creation |
| `POST /internal/proposals`, `GET /internal/proposals/{proposal_id}` | TASK-12 | Operator console | Starts and queries a proposal with `{issue_id, operator_patch?}` or `{kind: policy.draft.create, window_start, window_end, operation_ids[]}`. `sensor_rules` only through `operator_patch` |
| `POST /internal/proposals/{proposal_id}:revise` | TASK-12 | Operator console | Generates the next candidate from test feedback (at most 2 candidates) |
| `POST /internal/proposals/{proposal_id}:finalize` | TASK-12 | Operator console | Requests a `run_kind = candidate_final` run with the final candidate |
| `POST /internal/policy-diff:check` | TASK-14 | TASK-12 proposal service, console | Builds the candidate bundle (`candidate_digest`) and previews `permission_widening` |
| `POST /internal/regression-runs`, `GET /internal/regression-runs/{run_id}` | TASK-13 `regression-dispatcher` (operations project) | TASK-12 proposal service, TASK-14 releaser, TASK-02 discovery, measurement runs (TASK-15) | Writes the request to the `regression-requests` bucket, reads from `regression-reports` the report that the regression project runner produced by running `decision_replay` → E2E tests in order, and records it in `regression_runs` |
| `POST /v1/policy-changes`, `GET /v1/policy-changes/{change_id}` | TASK-14 | Operator console | Creates a change from a validated proposal and a `candidate_final` run and stores `permission_widening`; queries the diff, tests, approval, active version, and rollback evidence |
| `POST /v1/policy-changes/{change_id}/approve` | TASK-14 | An approver different from the proposer | Stores the approval digest |
| `POST /v1/policy-changes/{change_id}/activate`, `/rollback` | TASK-14 | Role `release_operator` | Activation (`approved → staged → activating`, started within 30 minutes of approval) and rollback (to the previous bundle bound at approval, no separate approval) |
| `POST /internal/discovery/snapshots`, `POST /internal/discovery/runs`, `GET /internal/discovery/candidates`, `POST /internal/discovery/candidates/{candidate_id}/promote`, `POST /internal/discovery/candidates/{candidate_id}/reject` | TASK-02 | Operator, analysis service | Snapshot creation, discovery runs, candidate queries, promotion after human review, and rejection |
| `GET /internal/discovery/snapshots/{snapshot_id}/files`, `GET /internal/discovery/snapshots/{snapshot_id}/callgraph` | TASK-02 `services/discovery/` | evidence-reader adapter (`discovery.source.read`, `discovery.callgraph.read`) | Reads a fixed snapshot, response 64KiB |
Internal APIs check the service identity and the allowed callers, and limit request rate and body size. They are not public APIs or current execution endpoints. Internal request retries are distinct from external action retries. The approval UI (`apps/console/policy-changes`) is owned by TASK-14.

<a id="api-implementation-contract-ref"></a>
## API Implementation contract

Every body is implemented with a strict schema and unknown fields are rejected (Go uses the strict decoding in [Normalization and Hashing](#normalization-and-hashing), Python uses Pydantic strict). UUIDs are server-issued identifiers, and digests are 64-character lowercase SHA-256 hex. The fields in the following table are included in the actual request/response.

| API | request fields | response and stored result |
| --- | --- | --- |
| `POST /v1/sessions` | workload_id, task_statement, requested_scope `{operation_ids[], target_ids[]}` | session_id, claim_code (single use, TTL 60 seconds), allowed_operation_ids, expires_at. actor and tenant are determined from the authentication context |
| `POST /v1/sessions/{session_id}:revoke` | reason | state=`revoked`; unused approvals get `revoke_reason = session_ended` |
| `POST /internal/sessions:revoke-scope` | hold_id, scope, scope_id. scope is `global`, `node`, `workload`, or `session` | revoked_session_ids. A repeated request with the same hold_id and scope returns the previous result; changing the scope for the same hold_id returns 409 |
| `POST /v1/sessions/{session_id}:refresh` | (current token) | New token and expires_at. The previous token is invalidated immediately |
| `POST /v1/sessions/{session_id}:claim` | claim_code (mTLS) | Session token (bound to the workload identity) and expires_at. Reuse returns `CLAIM_CODE_INVALID` |
| `POST /internal/service-sessions` | profile, issue_id?, candidate_id?, change_id?, snapshot_id?, action_id?, tenant, tool_budget?, ttl? | service_session_id, token, applied tool_budget, expires_at. Budget and TTL are clipped to the [service profile](#service-profiles) limits. The applied `tool_budget` is not null for any profile. If the profile is `activation_probe`, its value is `{probe_actions: {max, used: 0}}`. `max` is the caller's value clipped to the limit of 4, and it is 4 if the caller does not send one. The server also puts the same value in the `tool_budget` of the `service_session_created` event |
| `POST /v1/actions` | ClientAction, `Authorization: Bearer <session token>` | 202 for allow and approval_required; deny uses the HTTP status from the dictionary. The body is always `request_id, action_id?, decision_id?, verdict, execution_allowed, reason_codes`. On the standing rule path, the intent check waits synchronously within this request for up to 3 seconds and becomes `not_run` if it exceeds that. A resubmission with the same key and the same `raw_body_digest` returns the existing action and its latest decision |
| `POST /v1/actions/{action_id}:reevaluate` | expected action_digest | New request_id, decision_id, verdict, expires_at. Can be called even after a deny. A digest mismatch returns 409 `ACTION_DIGEST_MISMATCH`, and an already reserved action returns 409 `PERMIT_INVALID` |
| `GET /v1/actions/{action_id}/approval-contract` | Authentication context | ContractView, contract_digest, nonce (10 minutes, single use), intent check result (findings) |
| `POST /v1/approvals` | action_id, displayed_contract_digest, nonce, acknowledged_findings | approval_id, revision, contract_digest, policy_epoch, expiry. The server sets `max_actions` to 1 |
| `POST /internal/adapter/{adapter_id}/execute` | decision_id, action_id | 202. The adapter looks up the stored values and re-matches them |
| `POST /internal/dispatch/reservations` | decision_id, action_id, request_id, action_digest, wire_body_digest, policy_epoch, catalog_digest | The server creates the attempt_id and returns a DispatchPermit after COMMIT |
| `POST /internal/dispatch/permits/{permit_id}/check` | attempt_id, action_digest, policy_epoch, wire_body_digest | execution_allowed=true only for the first request that claims the unconsumed permit with CAS |
| `POST /internal/dispatch/attempts/{attempt_id}/outcome` | transition, observations[] (array of AdapterObservation), reason_codes | Ack after state CAS, storing `attempt_observations`, and audit COMMIT. `released` restores the budget in the global lock order |
| `POST /internal/dispatch/activation-probes` | change_id, client_request_key, target_epoch | activation_probe_id, expires_at |
| `GET /v1/actions/{action_id}/result` | Authentication context | ActionResult |
| `POST /internal/audit/events` | AuditEvent, producer mTLS | New event 201, same ID/digest 200, different digest 409 `EVENT_ID_CONFLICT` |
| `POST /internal/kernel/events:batch`, `POST /internal/lifecycle/events:batch` | `{batch_id, source_epoch, scope? (required for pod-watcher), records[], sequence_range_abandoned[] {from_seq, to_seq, reason, range_digest}, cursor? {scope, resource_version, expected_checkpoint_revision}, batch_digest}`. `batch_digest` = canonical digest(the request object without `batch_digest`). The source is determined from the mTLS SAN. Sequences start at 1 for each epoch | 200 `{batch_id, accepted_ids[], duplicate_ids[], rejected[] {id, reason_codes[]}, watermarks[] {source_epoch, acked_through}, checkpoint?}`. The watermark advances only up to the point where all preceding sequence numbers are stored, and moves past an abandoned range only after it is stored as an ObservationGap. For a record that received a rejection that cannot be accepted even on retry (`SCHEMA_INVALID`, etc.), the producer does not resend it with the same ID; it sends it as `sequence_range_abandoned(reason = record_rejected)` so that it is recorded as a gap, and then advances the watermark. The lifecycle cursor is returned as checkpoint `{scope, resource_version, checkpoint_revision}` after a successful [revision CAS](#lifecycle-checkpoint-revision-cas) and COMMIT, and is null if stale |
| `GET /internal/lifecycle/checkpoints?scope=` | scope | `{scope, resource_version, committed_at, checkpoint_revision}` |
| `POST /internal/control-health/leases` | ControlHealthLease | lease_until and current scope state. 403 if the caller SAN, component, and scope do not match `component_principals` |
| `POST /internal/control-health/observation-gaps` | `{scope, gap: {gap_id, stage, reason, source_epoch, start_at, end_at, loss_count, count_quality, recovery_state, evidence_refs}}` | 201 `{gap_id, result: "created", recorded_at}`; the same `gap_id` with the same body returns 200 `{gap_id, result: "existing", recorded_at}`; a different body with the same `gap_id` returns 409 `EVENT_ID_CONFLICT`. Responds only after the gap, audit, and outbox COMMIT |
| `POST /internal/control-health/probe-results` | probe_kind, scope?, scope_id?, node_uid?, boot_id?, stimulus_at? (required for `process`, `tcp`, and `file` pass), outcome (`pass`/`fail`/`unknown`), evidence_refs. Required combinations and reporting component per `probe_kind`: `process`, `tcp`, and `file` require node_uid and boot_id, scope is omitted or `node`/node_uid, and only the probe runner reports them. `export` is reported only by the TASK-07 audit-exporter, with scope `global`/`*` (no node_uid) or scope `node`/node_uid. The exporter cannot know the node's boot, so boot_id is not included for `export`. `receipt` uses scope `target`/target_id (no node_uid or boot_id, evidence-collector). Any other combination returns 422, and a report from another component, node/boot, or target returns 403. For `pass`, evidence_refs must not be empty | 201 `{probe_result_id}`. `outcome` is stored with the same value in the storage column `result`. `judged_at` is the time stored by the server. `stimulus_at` is the wire value for an answer probe pass and null otherwise, and `missing_events` is an empty array. control-health finds the evidence for an answer probe pass directly in the stored kernel events, as described in [TASK-10 3.2](TASK-10-correlation-health.md#32-control-health-decision). The `namespace` of a node probe is the Namespace of the reporting probe runner's certificate. The consecutive passes counted as release evidence for `probe_failed`, `lease_expired`, and `sensor_degraded` are only passes in the same scope and kind whose interval is the probe period ±2 seconds (answer 58–62 seconds, receipt 3–7 seconds). `export_lag` is released by the single latest `export` pass in the same scope after the hold was created. The latest cited pass must be within the maximum interval for its kind as of the release decision time |
| `POST /v1/runtime/session-workers`, `GET /v1/runtime/session-workers/{id}` | The supervisor submits worker_instance_id, runtime_process_epoch, supervisor/worker process hints, isolation profile digest, and controls report with workload mTLS + session token | TASK-10. POST returns 202 pending + worker_binding_id; GET returns the result for the caller's own session. Idempotent on worker_instance_id/digest. The caller does not issue the sensor exec_id/host PID |
| `POST /v1/runtime/session-workers/{id}:close` | Same supervisor identity, reason, and exit report evidence | TASK-10. New work permission is closed immediately; actual exit is confirmed by independent node/kernel evidence. Idempotent close, and the original evidence is preserved |
| `POST /v1/runtime/work-readiness/checks` | work_run_id, runtime_process_epoch, checkpoint, worker_instance_id, worker_binding_id, workload mTLS + session token | 202 pending + check_id, and the GET path. The actual binding is finalized by the server |
| `GET /v1/runtime/work-readiness/checks/{id}` | Same authentication and session context | WorkReadinessCheck and remaining_valid_ms. Other callers/sessions are rejected; work cannot start when expired/blocked |
| `POST /internal/control-health/pod-observation-results` | check_id, challenge_id, instance_binding, sensor_generation, rule_hash, filter_included, wal_fsync_ready, worker_binding_id?, root_exec_id?, worker_alive?, worker_evidence_refs[], reported_at, evidence_refs | Registered node-sensors only. 201 durable ack. A repeated report with the same nonce is accepted as a duplicate only with the same digest |
| `POST /internal/control-health/worker-observation-results` | worker_binding_id, challenge_id, instance_binding, resolved supervisor/worker identity, root_exec_id, exec_event_ref, worker_alive, observed controls, sensor_generation, reported_at, evidence_refs | Registered node-sensors only. Verifies that node/boot/nonce match and that the kernel row is COMMITted, then stores durably. Timeout 15 seconds, maximum node result lifetime 3 seconds |
| `POST /v1/runtime/work-events` | workload mTLS + session token. body `{event_id, event_type(agent_work_*), source_version, source_time, safe_payload {work_run_id, check_id, runtime_process_epoch, worker_instance_id, worker_binding_id, outcome?, reason?}}`. `session_id`, tenant, source, epoch, and digest fields are not sent, and 422 is returned if they are present. The gateway reads the WorkReadinessCheck of `check_id` using the verified caller SAN (`X-Agentarium-Peer-Identity`) and the session ID from the token (`X-Agentarium-Peer-Session`), and checks that the caller, session, workload, and the four IDs above match; if they differ it returns 403 `WORK_READINESS_BINDING_MISMATCH`, and a missing check returns 404 | The TASK-07 event ack as is (201 created, 200 duplicate `{event_id, result, received_at}`, 409 `EVENT_ID_CONFLICT`). Even if reporting is delayed, the event is linked to the original check but is not used as new work permission. The runtime accepts only a 201/200 ack for the same event_id as the start intent ack |
| `POST /internal/audit/work-events` | header `X-Agentarium-Peer-Identity` (runtime SAN), body `{context {session_id, tenant, workload_id, authenticated_actor}, check {check_id, work_run_id, session_id, workload_id, caller_identity, runtime_process_epoch, worker_instance_id, worker_binding_id, root_exec_id, instance_binding, sensor_generation, policy_epoch, state, audit_event_ref}, event}`. All keys are required (including keys that allow null), and 422 is returned if the shape is not exact | Same ack as the public path. Callers other than the gateway and peers that are not the runtime get 403; a mismatch between the event ID and the check/context gets 403 `WORK_READINESS_BINDING_MISMATCH`; `state = pending` gets 503 `WORK_READINESS_EXPIRED`; an event_type outside agent_work_* gets 422. Assignment follows [TASK-07 work readiness check and multi-session audit](TASK-07-audit-store.md#work-readiness-check-and-multi-session-audit-required) |
| `POST /v1/runtime/probe-reports` | Same body as above or ControlHealthLease | The gateway relay result as is |
| `POST /internal/holds` | scope, scope_id, reason, reason_detail? (required only when `reason = risk_event`, with a value from the `hold.reason_detail` enum; sending it with any other reason returns 422), evidence_refs, operator_request? (required when `reason = operator_stop`: `{authenticated_actor, console_request_id, justification}`) | hold_id, decision (`created`/`existing`/`rejected`), reason_codes. A permission denial for an authenticated request returns HTTP 403, hold_id=null, decision=rejected, reason_codes=[HOLD_REQUEST_DENIED] |
| `POST /internal/holds/{hold_id}/release` | `{justification, evidence_refs, probe_result_ids?, operator_approval?}`. Automatic release uses the owning component's SAN and `probe_result_ids`; release for security reasons uses the console BFF and `operator_approval {authenticated_actor, approved_at, console_request_id}`; owner-confirmed release (`policy_activation`, `start_unknown`, `db_unavailable`) uses only the owning component's SAN and the supporting `evidence_refs`. Sending both optional fields returns 422. `release_ref` is not accepted as input | `{hold_id, released_at, release_ref}`. The server creates `release_ref`, COMMITs it in the same transaction as `hold_released`, and then responds. If a request that would yield the same `release_ref` is sent again for an already released hold, the stored response is returned with 200. A missing hold returns 404 `RESOURCE_NOT_FOUND`; any other already released hold and insufficient evidence return 409; owner or operator verification failure returns 403. Resumed heartbeats alone do not release a hold |
| `GET /internal/holds?owner_component=` | owner_component (must equal the `component_principals.component` of the caller SAN) | `{holds: [{hold_id, scope, scope_id, reason, owner_component, created_at}]}`. Unreleased holds only. Specifying another component returns 403 `HOLD_REQUEST_DENIED` |
| `POST /internal/runtime/start-permits` | runtime binding, runtime_profile_digest, sensor/guard generation, check_snapshot_id, prepare_event_id | StartPermit. The same prepare_event_id/digest returns the same result; a different digest returns 409 |
| `POST /internal/runtime/start-permits/{id}/consume` | Same binding, generation, check_snapshot_id, consume_key | Only the first consumption COMMIT gets start_allowed=true. A resubmission gets already_consumed=true + start_allowed=false |
| `POST /internal/runtime/start-attempts/{id}/transitions` | transition_event_id, binding_digest, state, evidence references | Ack after CAS and audit COMMIT. An illegal transition returns 409 |
| `GET /v1/actions/{action_id}/timeline` | Authentication context, cursor, limit | [Timeline response schema](#timeline-response-schema) |
| `POST /v1/actions/{action_id}/resolutions` | attempt_id, resolution (`no_effect`/`effect_confirmed`/`mismatch`), evidence_refs (required) | resolution_id, `unknown_resolved` event |
| `POST /internal/issues` | source, action_id?, gap_id?, intent_check_id?, finding_id?, evidence_ids | issue_id. If `source = network_finding`, `finding_id` is required and `action_id`, `gap_id`, and `intent_check_id` are null |
| `POST /internal/proposals` | `{issue_id, operator_patch?}` or `{kind: policy.draft.create, window_start, window_end, operation_ids[]}` | proposal_id, state=`draft`, `initiated_by_actor` recorded |
| `POST /internal/intent-checks` | action_id, contract_digest (digest of the ContractView), rendered_contract | IntentCheckResult (200 even if `intent_check_status` is `not_run`) |
| `POST /internal/policy-diff:check` | base_bundle_digest, patch | candidate_digest, `permission_widening {widened, items[]}` |
| `POST /internal/credentials:resolve` | attempt_id, adapter_id, credential_binding | `{secret_version, header_name, header_value, expires_at}`. Only the version goes into the audit. The allowlist is `credential_bindings`. Rejection is `CREDENTIAL_UNAVAILABLE` |
| `POST /internal/regression-runs` | run_kind, fixture_scope[] (array of scopes; `["core", "intent"]` for `candidate_final`), extra_fixture_ids?, proposal_id?, candidate_digest, baseline_bundle_digest, environment_id. For `candidate_final`, the runner includes the holdout automatically | 202 + run_id, state=`not_run` (before execution). After completion, `GET .../{run_id}` returns fixture_set_digest (computed by the runner), report_digest, the decision_replay summary, and release_eligible |
| `POST /v1/policy-changes` | proposal_id (validated), run_id (`run_kind = candidate_final`) | change_id, state=`proposed`, `created_by_actor`, permission_widening. Other run_kind values return 422 |
| `GET /v1/policy-changes/{change_id}` | Authentication context | diff, report, approvals, active epoch, component acks, rollback evidence |
| `POST /v1/policy-changes/{change_id}/approve` | base/candidate/report/component digests, fixture_set_digest, widening_acknowledged_items, scope, expiry, nonce | approval_digest. On approval, checks that the report's `required_fixture_ids ⊆ fixture_ids` and that the approver ≠ `initiated_by_actor` and `created_by_actor` |
| `POST /v1/policy-changes/{change_id}/activate` | expected epoch | hold_id, stage, desired/observed epoch, probe status |
| `POST /internal/discovery/candidates/{candidate_id}/promote` | promotion_kind, reproduction_run_id, review_note | state=`promoted`. 409 if not `reproduced`. `allow_operation` for an `observed_not_static` candidate also returns 409 |

Queries apply the caller's tenant/owner scope. Registered service callers also have their allowed operations restricted by the server role mapping. Permissions cannot be widened by adding a caller identity to the body. Rate limits start at 10 req/s per user session, 50 req/s per workload, and 1MiB/100 events per producer batch, and a 429 includes Retry-After.

<a id="identity-pki-and-network-contract-ref"></a>

## Identity, PKI, and network contract

### Service PKI and identifiers

| Item | contract |
| --- | --- |
| CA | One CA pool of Certificate Authority Service (DevOps tier). The only principal that calls CAS is the identity service (`services/identity/`, KSA `workload-identity`), and this service issues every workload, service, and node bridge certificate. The limits of the DevOps tier (certificate lifetime, issuance rate, audit) are Q0 |
| Issuance path | `POST /internal/workload-certificates`. The Pod and KSA are confirmed with TokenReview (audience `agentarium-identity`), the role is looked up in `registered_workloads`, and then the server sets the SAN. The identity requested in the CSR is not used |
| Service SAN | `spiffe://agentarium.internal/ns/<namespace>/sa/<ksa>` |
| Execution Pod SAN | In addition to the service SAN, `spiffe://agentarium.internal/ns/agent-exec/sa/<ksa>/pod/<pod_uid>` |
| node bridge SAN | `spiffe://agentarium.internal/node-bridge/<node_uid>/<boot_id>`. Rejected if the boot ID changes. Because there is no ns/sa, it is not looked up in `registered_workloads` but resolved to the fixed principal `node-runtime-bridge`, and node/boot is checked against `node_boot_generation` |
| certificate template | The existing CA pool and CA are kept, and two templates in the same location are used. The service profile allows `serverAuth` and `clientAuth`, and the execution Pod, probe, fixture, and node bridge profiles allow only `clientAuth`. The template is selected by the role verified by identity, not by the CSR or the caller. The X.509 baseline of the pool/template is not duplicated, and TASK-06 IAM allows only issuance that names the two templates ([TASK-03 3.3.1](TASK-03-identity-approval.md#331-service-mtls-pki)) |
| Lifetime and renewal | 24 hours, renewed at 50% of the lifetime |
| trust bundle | ConfigMap `agentarium-trust` (in each Namespace). During rotation, the old and new roots are kept together |
| principal resolution | The server looks up `registered_workloads(namespace, ksa, role, adapter_id?, service_principal)` by the ns/sa of the SAN to determine the caller principal and adapter_id. Checks such as "same adapter only" are done with this value |

**KSA and label rules:** The Pod label `app.kubernetes.io/name` must equal the name of that Pod's KSA (checked by TASK-01 Admission). NetworkPolicy and the SAN mapping use this name.

| Namespace | KSA (= label) |
| --- | --- |
| agent-exec | `agent-runtime`, `probe-runner`, `start-fixture` |
| agent-control | `policy-gateway`, `workload-identity`, `coordinator`, `credential-broker`, `node-readiness`, `intent-checker` |
| agent-adapters | `kubernetes-reader`, `receiver-sender`, `model-adapter`, `evidence-reader`, `probe-runner` |
| agent-observe | `audit-writer`, `audit-exporter`, `audit-verifier`, `audit-retention`, `evidence-collector`, `pod-watcher`, `control-health`, `correlation`, `start-coordinator`, `drift-probe`, `timeline`, `policy-proposer`, `discovery` |
| agent-sensors | `tetragon` (including the exporter sidecar), `lifecycle-recorder`, `runtime-guard`, `netpol-collector` |
| agent-release | Production project: `releaser`, `regression-dispatcher`. Regression project: `releaser`, `regression-runner`, `decision-replay` |
| agent-targets | `receiver`, `probe-sink`, `start-marker` |

### Console path and IdP

- The OIDC IdP is Google (`https://accounts.google.com`). The discovery document is kept as static configuration, and the token endpoint `oauth2.googleapis.com` and JWKS `www.googleapis.com/oauth2/v3/certs` are accessed through Private Google Access. Whether these two hosts respond on the PGA VIP is confirmed by the owners (TASK-03, 06), and until confirmed it is a Q0 item.
- The console comes in through a single external HTTPS Load Balancer. The LB splits the static UI and the API by path and sends all API traffic to the console BFF of the identity service. The BFF checks the OIDC session cookie and CSRF, forwards the request to the target service over mTLS, and inserts `X-Agentarium-Console-Actor` and `X-Agentarium-Console-Roles`. Target services trust these headers only when they come from a connection with the identity service SAN.

| LB path | Target |
| --- | --- |
| `/`, `/assets/*` | `apps/console/` static UI |
| `/v1/sessions*`, `/v1/approvals*`, `/v1/actions/*/approval-contract` | identity service (handled directly) |
| `/v1/actions/*/timeline`, `/v1/actions/*/resolutions` | BFF → timeline (TASK-11) |
| `/v1/actions/*:reevaluate`, `/v1/actions/*`, `/v1/actions/*/result` | BFF → gateway (TASK-04) |
| `/v1/policy-changes*` | BFF → releaser (TASK-14) |
| `/console/internal/proposals*`, `/console/internal/discovery*`, `/console/internal/holds` (`operator_stop` creation), `/console/internal/holds/*/release` | BFF → TASK-12 proposal service, TASK-02 discovery, TASK-10 control-health |

### Operator stop

When an operator finds abnormal behavior that automatic rules do not catch, the operator places an `operator_stop` hold from the console. The scopes allowed for this reason are four: `global`, `node`, `workload`, and `session`; the `target` scope is not allowed (422). It is a stop that revokes every session within the scope, and a stop that blocks only actions going to a specific target is not part of this contract.

| Item | Rule |
| --- | --- |
| Creation | The console BFF calls `POST /internal/holds` (`reason = operator_stop`) with `operator_request {authenticated_actor, console_request_id, justification}`. TASK-10 confirms that the caller is the identity service SAN of the console BFF, and then confirms that `X-Agentarium-Console-Roles` contains `operator` and that `operator_request.authenticated_actor` equals `X-Agentarium-Console-Actor`. Identity, role, or actor verification failures are rejected with 403, and a missing required body with 422 |
| New requests | Same as other holds. The coordinator and the gateway do not reserve or forward new actions within the scope |
| Sessions | After storing the hold, TASK-10 calls `POST /internal/sessions:revoke-scope {hold_id, scope, scope_id}` (TASK-03). Identity finds the active sessions within the scope, changes them to `revoked`, invalidates their tokens, and cancels unused approvals with `revoke_reason = session_ended`. The approval cancellation reason caused by session termination keeps the existing contract, and operator intervention is distinguished by the `operator_stop` hold and the `hold_requested` event. If the call fails, TASK-10 requests again with the same hold_id and scope, and keeps the hold until completion. Selection of target sessions and idempotency storage are owned by TASK-03, and no sessions SELECT permission is added to TASK-10 |
| Running Pods | They are not deleted or restarted. Code inside the Pod can keep running, but every external effect goes through the gateway, so the hold blocks it. A forced Pod termination is done only through the break-glass procedure of the operations runbook (TASK-16) |
| Release | Like security reasons, it is released only with operator approval (`operator_approval`; the server creates `release_ref = operator:<authenticated_actor>:<console_request_id>`). Releasing does not restore cancelled sessions and approvals |
| Records | `hold_requested` (requester is the console BFF, including the operator `authenticated_actor`) and `hold_released` events, plus session and approval cancellation events, are recorded |
### Workload certificate bootstrap wire format

`POST /internal/workload-certificates` uses the same format for initial certificate issuance and renewal. This table does not change the CSR and projected token verification in TASK-03.

| Direction | Fields |
| --- | --- |
| Request | `{csr: string, token: string}`. `csr` is a PEM PKCS#10 containing an ECDSA P-256 public key; the CSR string must be 8KiB or less, and only a single `CERTIFICATE REQUEST` PEM block is allowed. The server verifies the CSR signature and then uses only the public key. `token` is a Pod-bound projected token with audience `agentarium-identity`. A SAN requested by the caller is not used as a basis for permissions |
| Success (200) | `{certificate: string, certificate_chain: string[], serial: string, expires_at: string}`. These are the leaf PEM, the PEM chain starting from the issuer, the hex serial, and the UTC RFC3339 expiry time |
| Failure | Uses the COMMON error envelope. Authentication failure is 401 (`AUTH_REQUIRED`), schema or CSR condition violations are 422 (`SCHEMA_INVALID`), a request body over 64KiB is 413 (`BODY_TOO_LARGE`), a method other than POST is 405 (`reason_codes = []`), a `Content-Type` other than `application/json` is 415 (`SCHEMA_INVALID`), and a body read failure is 400 (`SCHEMA_INVALID`). Temporary dependency failures return 503 with `Retry-After: 2`. The 503 reason code is `STATE_STORE_UNAVAILABLE` for DB or Kubernetes API lookup failures and unclassified errors, and `CREDENTIAL_UNAVAILABLE` for CAS issuance failures |

Service and adapter clients that connect directly to identity use the trust bundle to verify the identity server's chain, validity period, serverAuth EKU, and exact service URI SAN. They confirm that the received leaf matches their key, that it has exactly one expected service SAN, its serverAuth and clientAuth EKUs, and its expiry time, and then atomically replace the key/certificate in memory. Service and adapter certificates are renewed at 50% (12 hours) of their 24-hour lifetime.

Runtime, probe, and fixture Pods and the node runtime bridge use the gateway-relayed path in TASK-03 3.3.2. The TLS peer of these clients is the gateway, so they verify the gateway server's chain, validity period, serverAuth EKU, and exact service URI SAN. The gateway forwards the bootstrap body (CSR and token) to identity unchanged, and the final issued SAN is determined by the identity that identity verified. Runtime, probe, and fixture certificates use a SAN bound to the Pod UID and a clientAuth-only EKU, and are renewed at 50% of their 24-hour lifetime. Node runtime bridge certificates use a SAN bound to the node UID and boot ID and a clientAuth-only EKU; their lifetime is 24 hours, and they are reissued when the boot ID changes (TASK-03 3.3.1). The serverAuth requirement and the 50% renewal rule for services and adapters do not apply to the node runtime bridge.

The hostNetwork agent-sensors service workloads (`tetragon` exporter, `netpol-collector`) also obtain certificates through the same gateway-relayed path. Because the TLS peer is the gateway, the client verifies the gateway server certificate as described above. The issued certificates use the same kind of service SAN as other services (`ns/agent-sensors/sa/<ksa>`), serverAuth and clientAuth EKUs, and a 24-hour lifetime, and are renewed at 50% (12 hours) of their lifetime. Identity records the node/boot of the Pod's `spec.nodeName` in the issuance record and issues a new certificate when the boot changes and the Pod restarts.

This wire correction keeps the existing per-role PKI and relay path contract, and does not mean that real CAS/GKE verification or the node runtime bridge issuance implementation is complete.

### NetworkPolicy and Cloud SQL Access

- The NetworkPolicy allow table (TASK-06) is generated mechanically with one row for each (caller, API) pair in the [internal API responsibilities](#internal-api-responsibilities) table, plus infrastructure rows (DNS, metadata server, PGA VIP, kube-apiserver, Cloud SQL, IdP). TASK-06 owns the full per-role YAML.
- Every Pod that uses Cloud SQL has a Cloud SQL Auth Proxy native sidecar and metadata server egress. No GSA annotation is put on the KSA; only the Proxy uses the per-KSA DB GSA through `--impersonate-service-account`. The DB GSA has `roles/cloudsql.client` and `roles/cloudsql.instanceUser` restricted to the instance, `roles/serviceusage.serviceUsageConsumer` on the project, and a DB IAM user, and each KSA can impersonate only its own DB GSA. Google API permissions other than DB are placed directly on the KSA principal. The IAM table and the specific permissions follow TASK-06.
- The internal retries used by the metadata token source in `golang.org/x/oauth2/google` are an allowed exception to "no hidden retries". These retries do not resend external action calls.

<a id="policy-deployment-contract-ref"></a>

## Policy Deployment contract

| Item | contract |
| --- | --- |
| desired_bundle | `desired_bundle(environment PK, bundle_id, artifact_digest, object_uri, set_by_change_id, set_at)`. One row per environment, written only by the releaser. `object_uri = gs://<bucket>/bundles/<artifact_digest>.tar.gz` |
| Loading | The gateway and adapters read this row every 2 seconds, fetch the object, verify the digest and signature, and then load it. Adapter constraints are also read from `data.adapter_constraints` of the same bundle; ConfigMaps are not used |
| digest | `artifact_digest` = SHA-256(tarball, including `.signatures.json`). `candidate_digest` = canonical digest (the file list excluding the signature file and the SHA-256 of each file). Regression tests and approval use `candidate_digest`, and load confirmation uses `artifact_digest` |
| Activation order | Create the `policy_activation` hold → update `desired_bundle` → the leases of all expected replicas (based on Deployment `status.replicas`) report `loaded_artifact_digest` → `active_policy` epoch CAS (update `expected_opa_revision`, call `revoke_approvals_for_policy_change`) → activation probe → release the hold or roll back. Ack timeout is 120 seconds |
| Signing | ES256. The operational key is Cloud KMS `EC_SIGN_P256_SHA256` (keyID `prod-v1`). The releaser's `packages/bundles` builds the OPA bundle signature format with a KMS `crypto.Signer`. The owner (TASK-14) confirms from the OPA source whether OPA supports ES256 verification and what the signature file format is; until confirmed, this is Q0 |
| Verification key | The public key is distributed as the ConfigMap `agentarium-bundle-keys`. The regression project uses a separate key `regression-v1`, and the operational gateway trusts only `prod-v1` |
| decision_inputs export | The TASK-07 exporter exports `decision_inputs` as NDJSON batches to the dedicated bucket `decision-input-exports` in the operations project (30-day retention and soft delete, signed manifest chain `chain_id = gcs_decision_inputs`). The `decision-replay` SA in the regression project is given only `roles/storage.objectViewer` on this bucket and no access to the operational DB |
| rollback | The activation order above is performed again with the previous compatible bundle, and the epoch increases |

<a id="regression-test-contract-ref"></a>

## Regression Test contract

| Item | contract |
| --- | --- |
| Cross-project relay | Callers in the operations project (TASK-12 proposal service, TASK-14 releaser, TASK-02 discovery, TASK-15 measurement run) do not call the regression project runner directly. The TASK-13 `regression-dispatcher` (KSA `regression-dispatcher`, Go) in the operations project `agent-release` receives `POST /internal/regression-runs` and writes a request object to the GCS bucket `regression-requests` (`requests/<run_id>.json`: request fields, the pre-signature files of the baseline and candidate bundles, and `candidate_digest`). The runner in the regression project (KSA `regression-runner`) polls this bucket, runs the request, and writes the report and `report_digest` to the bucket `regression-reports` (`reports/<run_id>.json`). The dispatcher reads the report, recomputes and compares `report_digest` with `packages/canonical/`, and then records it in `regression_runs`. Cross-project IAM for this relay is opened only on these two buckets (regression runner: objectViewer on `regression-requests` and objectCreator on `regression-reports`; dispatcher: the reverse). The complete set of cross-project grants is only four combinations: these two plus the regression decision-replay's read of `decision-input-exports` and its lookup of the manifest public key ([TASK-06 3.3](TASK-06-egress-credentials.md#33-secrets-and-wif-permissions-ref), [#97](https://github.com/Beaver-Dam-Community/Agentarium/issues/97)). Both buckets have 30-day retention and soft delete |
| fixture scope | `core`, `intent`, `discovery`, `startup_gate`, `measurement`. The required set for each scope is in `fixture_registry`. `startup_gate` is not required for release |
| fixture set | A request sends only `fixture_scope[]` (an array of scopes) and optional `extra_fixture_ids`. `required_set_digest` is the canonical digest of the union of required fixtures for the sorted scope list. The runner adds the holdout (`candidate_final` only), computes `fixture_set_digest`, and returns it ([normalization and hashing](#normalization-and-hashing)). The report contains `fixture_set_digest, fixture_ids[], required_set_digest, required_fixture_ids[]`, and TASK-14 checks `required_fixture_ids ⊆ fixture_ids` in the candidate_final run |
| outcome | Compared using the [Outcome](#policy-improvement-testing-and-discovery) object |
| Approval automation | A synthetic approver dedicated to the regression project (test IdP user `regression-approver`, different from the operational issuer) performs approvals and acknowledgements. The operational environment does not accept this identity |
| Execution unit | Regression Job timeout of 60 minutes, sharded by fixture class (TASK-16) |
| `ai_created_allow_count` | (Number of decisions whose final verdict is more permissive than `rego_result.verdict`) + (number of policy changes activated without human approval). The permissiveness order is `deny < approval_required < allow` |
| `ai_proposed_widening_count` | The sum of widening items in activated policy changes that came from proposals where the model produced `builder_params` (proposals with a `model_id`). Each item needs an acknowledgement before it can be activated, so this is the amount of AI-originated widening that a human confirmed. It is not part of the `release_eligible` invariant and is reported together with the results and measurements |
| Demo determinism | Demo step 2 (request containing email) is submitted with a fixed payload by a deterministic client. A run in which the LLM builds the request directly is a separate optional demo. The order is candidate_final run → policy change registration |

<a id="error-state-and-health-defaults-ref"></a>

## Error, state, and health defaults

- HTTP 401 authentication, 403 policy/permission, 404 not found or out of scope, 409 body reuse/epoch conflict, 413 size, 422 schema, 429 rate limit, 503 required dependency/observation unavailable. An error body returns only `request_id`, `reason_codes`, and, if present, `action_id` and `decision_id`. For another tenant's resources, existence is hidden and the response is 404 `RESOURCE_NOT_FOUND`. 429 and 503 include `Retry-After` (seconds, starting value 2).
- `approval_required` is 202 + `execution_allowed=false`, and `allow` is 202 + `execution_allowed=true`. A 2xx does not mean completion. An expired session token gets 401 without reaching Rego.
- verdict, execution_state, alignment, and evidence_level are different axes ([enum definitions](#enum-definitions)). Original facts are not deleted.
- **Initial implementation values:** decision/dispatch permit TTL 10 seconds, start permit TTL 10 seconds (server DB clock), NRI path guard deadline smaller than `plugin_request_timeout` (contract below), heartbeat 5 seconds, health lease TTL 15 seconds, collection delay 10 seconds, clock skew 2 seconds, external timeout 10 seconds, claim_code TTL 60 seconds. Automatic redirect/retry/HTTP2/keep-alive are disabled. The rationale before and after any adjustment is recorded.
- Not only the heartbeat but also boot/sequence, hooks, active policy, and correct-answer probes are checked. If required hooks/events are not visible, the state is not healthy.
- Sending, model disclosure, and changes require user approval or a standing rule. The default failure response is to hold new execution, and in the MVP queries are held as well. No exception is made for a failure to store the minimal audit record.
- Inability to COMMIT to the DB is a hold. External export delay is `degraded`, and becomes an `export_lag` hold when it exceeds the lag limit.
- A hold is a `holds` row. If the impact cannot be narrowed to a specific session, the entire shared workload is held. For temporary failures with a clear cause (export delay, DB restart, temporary probe failure), the owning component releases the hold automatically after the probe passes and records a `hold_released` audit event. Security reasons (drift, bypass, sensor tampering, alignment mismatch, risk events) are released only with operator approval.

<a id="agent-work-startup-contract-ref"></a>

## Agent work startup contract

**MVP requirement:** Agent work starts only after observation readiness of the node and the Pod, followed by durable confirmation of kernel execution observation for the session-dedicated worker and of its session link. A trusted supervisor in one Pod/single container manages several dedicated workers, and each worker handles only one session during its lifetime. This contract is enforced by a trusted fixed initialization program and the application session bridge; observing the first execution of the initialization program itself is in the scope of `startup_guard_gate`, an optional hardening feature. Even without NRI support, this work startup contract cannot be skipped. The current implementation, deployment, and functional verification state is planned/not_run.

### Required execution order

The following is the verification order for releasing user work. In the physical implementation, a trusted bootstrap worker can be created as an observation target first after authentication and assignment, and that creation is within the initialization scope. Registration → worker witness → the final work-readiness API confirm the readiness of the node, Pod, and worker. Do not create a cycle in which worker registration requires the final WorkReadinessCheck. Before readiness is complete, user payloads, model/tool calls, and work queue consumption are not released to the worker.

1. **Trusted initialization:** The fixed entrypoint of the approved image starts only the authentication, assignment lookup, and readiness check functions. Before readiness, it does not call the ADK runner, call models, run tools, consume the work queue, process user payloads, or access session scratch data. This initialization does not mean adding a Kubernetes init container.
2. **Node readiness:** TASK-01 prevents placement on unready nodes with a startup taint, and TASK-09/10 check the actual node's sensor, required hooks/rules, exporter/WAL, collection ack, correct-answer probe, and active policy state. The fact that a sensor was installed on the node pool, or Pod `Ready` alone, is not enough to pass.
3. **Pod readiness:** Link the Pod UID in the certificate SAN to the trusted lifecycle record, and determine the cluster UID, Pod UID, node UID, boot ID, full container ID, restart instance, cgroup inode, approved image digest, sensor generation, and rule hash. This requires confirmation from node-sensors that the container is actually included in the observation rules/filters, and the lifecycle DB COMMIT ack. Pending API metadata, unknown filter application, WAL unavailability, exceeded collection limits, and related holds mean not ready.
4. **Create, observe, and link the dedicated worker:** The supervisor creates a fresh exec worker with a minimal environment/FDs and puts it in a trusted bootstrap wait state with no user payload. It is registered under the COMMON [session-dedicated worker contract](#session-dedicated-worker-contract), and the SessionProcessBinding is COMMITted as `observed` after comparing it against the actual node's process identity and the kernel `process_exec` storage ack. A session_id/argv/PID submitted by the worker itself is not enough to pass. On termination, duplication, observation loss, or unknown identity, user work does not start.
5. **Session permissions and budget:** The server checks the session token's claimed workload identity, owner, expiry, revocation, allowed operations, and remaining session budget. A user's session creation is consent to work assignment, not approval of every action. Per-action user approval/standing rule checks keep the existing gateway and dispatch contract, and the readiness check does not consume action budget or approval counts in advance.
6. **Work start:** TASK-15 checks for a valid `WorkReadinessCheck` and receives the `agent_work_start_requested` audit COMMIT ack; then, only if the validity period remains, it releases only the waiting worker with the same worker_instance_id/binding/root exec as the server check, and starts the work/turn of that session runner. It is not passed to another worker like a permit. If it expires while waiting for the ack, a new check is required, and `agent_work_started` is reported after the actual runner call. Session creation, assignment, token claim, and readiness check are recorded separately from successful work start.

<a id="pod-readiness-check-and-freshness-ref"></a>

### Pod readiness check and freshness

- `POST /v1/runtime/work-readiness/checks` and result lookup use only the existing gateway path. The runtime does not receive the node management socket, start coordinator credentials, or Kubernetes write permissions. It requests with workload mTLS + session token and submits `work_run_id` (UUID, per work/turn), `runtime_process_epoch`, `checkpoint` (`start`, `resume`, `control_step`), `worker_instance_id`, and `worker_binding_id`. The worker references are compared with the server registration, and the root exec ID is determined from the node witness. The caller does not decide node/boot/container/generation.
- TASK-10 creates a `pending` check and assigns a nonce challenge only to that node/boot. The TASK-09 exporter picks it up through the existing outbound health query, freshly checks whether the actual cgroup is included in the filter, the sensor/WAL state, and the liveness, PID/starttime, and root exec identity of the linked worker, and reports the result over management mTLS. A readiness result for another Pod on the same node, or an old heartbeat, is not substituted for this Pod's result. The challenge, report, and final judgment are durably recorded in TASK-10.
- The initial challenge timeout is 15 seconds. It does not hold a DB transaction/lock while waiting for the node response. After the node answers, the final transaction rechecks the binding, the worker observed state/liveness evidence, generation, policy, related leases/holds, session, and budget, and COMMITs `work_readiness_passed` together with the outbox. A `ready` response is not given before the COMMIT is confirmed. The usage limit of the result is **at most 3 seconds** from the final check time, and does not exceed the expiry of related leases or the validity period of the node report. Lock/generation ordering follows the existing COMMON order.
- The maximum lifetime of the node result is also 3 seconds, and the upper bound is verified using the monotonic elapsed time between sending and receiving the server challenge and the receive time. Freshness is not authenticated by the time sent by the node alone. The initial values of 15 seconds/3 seconds are kept in the TASK-16 environment lock, and any change is made after measuring latency and load in Q0, with the rationale and regression tests recorded.
- The result GET can be queried only by a caller with the same mTLS, session, and work_run_id. On expiry, binding change, or a hold, a past `ready` is not reused. The gateway also sends the remaining validity time in the response, and the runtime subtracts the monotonic elapsed time of the GET round trip and uses the result only if it can start immediately. If the time, response, or COMMIT is unknown, work is not started and a new check is requested.
- This check is not a `start permit` or a `dispatch permit`. It does not authorize native container start, approval consumption, or external effects, and does not guarantee exactly-once execution. A new check ID is used for each checkpoint, and a timeout is not turned into automatic execution of new work or actions. Crash recovery of work already started is decided after a separate state comparison, and an unknown start result is not automatically re-executed.

### Multiple sessions, restarts, and failures

Even after the Pod's initial readiness, checks are repeated **at the first task of each new session, at the next task/ADK turn, at resumption after an approval wait, and at the control point before each model or tool call**. The permission and budget check for session A is not reused for B. A node/POD observation anomaly holds new tasks, resumptions, and control points for all sessions in that Pod, while per-session revocation or budget exhaustion rejects only that session. An anomaly in shared state whose impact scope cannot be narrowed is escalated to a workload-scope hold.

Pod replacement, container restart, and runtime process restart start with the local gate closed and discard previous readiness results. Sensor restart, rule reload, node reboot, and policy epoch change also invalidate the results. Worker termination or restart closes/invalidates the corresponding binding and check. A sensor generation change sets the binding to invalidated and holds the worker at the next control point. After task state reconciliation and termination confirmation, the work restarts with a new worker_instance_id/root_exec_id/binding, and past actions are not automatically re-executed. A worker is not reused for a different session. When the supervisor restarts, it does not keep using past workers as orphans; it terminates/reconciles them and creates new workers in a new epoch. When the runtime submits an action or requests an execution re-evaluation (:reevaluate), the gateway receives `X-Agentarium-Work-Run-Id` and `X-Agentarium-Work-Readiness-Check-Id` as untrusted references and checks them against the server-recorded caller/session/worker binding, expiry, current generation, hold, and policy. The service session and console query and approval APIs do not require these runtime headers.

Immediate forced termination of local CPU code that is already running is not guaranteed. The trusted runner stops at the next control point, and the gateway/dispatch rejects subsequent external actions. Unplanned failures between the readiness check and the actual task start, and heartbeat/challenge detection delays, remain. The failure occurrence, detection, hold, last pass, and next block times and the gaps between them are measured and reported. In an execution model where malicious code can tamper with the trusted runner itself, local execution enforcement is not claimed from the application gate alone. Isolation of arbitrary shell/native code and adversarial session execution is outside the current MVP scope.

### Two layers of start guarantee

| contract | Required | On failure |
| --- | --- | --- |
| Task start gate | MVP required, all runtime Pods/sessions | Task start and resumption are forbidden for the Pod/session whose readiness is unknown. If a required test fails, the MVP/policy release is incomplete |
| `startup_guard_gate` | Optional hardening before the container's first target program | Even if `unsupported`, the task start gate is still required. Deployment is held only for profiles that need this hardening |

<a id="session-dedicated-worker-contract-ref"></a>

### Session-dedicated worker contract

**Adopted decision:** Instead of multiple ADK sessions in a shared Python process, the MVP uses a fresh-exec process per session. The Pod/container is shared, and the UID stays at 10001 from the current Admission. This provides a per-process address space and one-to-one session ownership, but it is not claimed that adversarial code's access to files and credentials under the same UID/volume/kernel is fully blocked. Detailed settings and unverified hardening are in [the session isolation scope of TASK-15](TASK-15-runtime-integration.md#session-isolation-scope-and-hardening-options).

1. The supervisor records the actual Popen child handle, local PID/start ticks, and PID namespace inode, and maps them to a dedicated IPC channel and a worker_instance_id (UUID). The worker is not given other sessions' context, session tokens, mTLS keys, or projected identity tokens. The supervisor handles gateway HTTP authentication, assignment/claim, and the readiness check. A session_id in the worker's input is not used as IPC routing authority.
2. After the worker's final exec, the trusted bootstrap applies the required isolation settings before loading threads/ADK/user data, sends the controls ack, and then waits. Calling prctl only before exec is not taken to mean the dumpable setting is preserved. A failure of a required setting blocks the task with `WORKER_ISOLATION_NOT_READY`. Isolation logic is not placed in the preexec_fn of a multithreaded Python parent.
3. The supervisor registers via `POST /v1/runtime/session-workers`. The same worker_instance_id/registration digest returns the same binding, and different content returns 409. Only one pending/observed binding is allowed per session. close/invalidated is not reverted. The server checks the claimed workload/session, epoch, and current lifecycle, and caller process hints are still unconfirmed location information.
4. TASK-10 assigns a nonce dedicated to its own node/boot as `pending_worker_observation_challenges` in the existing outbound health query. TASK-09 resolves the local PID and start ticks to a host PID in the corresponding container/PID namespace, and verifies the live supervisor/worker as well as the approved image's fixed worker command and parent relationship. Even with the same PID, a different start ticks/namespace/container is rejected, and if the mapping is multiple or unknown it does not pass.
5. The node witness's host PID/starttime, container, and node/boot are uniquely matched against the exec_id/parent lineage of the worker's final `process_exec` COMMITted to TASK-07. The node does not create arbitrary exec_ids. The returned `exec_event_ref` is a reference to a stored row whose source/node/boot/container/time match has been verified, and it cannot be replaced by a simple argv nonce or an application start marker. Worker liveness is separate node evidence and is not accepted from exec observation alone.
6. TASK-10 COMMITs the SessionProcessBinding and `session_worker_observed`/outbox in the same transaction. The supervisor releases the task only when all of the following are present: worker observed, a fresh node/Pod/worker challenge, session permission/budget, a valid WorkReadinessCheck, and the start-intent audit ack. Loss of the registration, kernel exec, or connection COMMIT ack is reconciled by query/idempotent retry, and a task timeout is not turned into automatic execution.
7. SessionProcessBinding and the derived KernelSessionAttribution are kept for at least the initial 30-day kernel source retention period. Events that arrive late after termination are linked only by the original process identity, time interval, and observed parent relationship. PID reuse, loss of parent relationship, multiple distinct binding candidates, and events from the shared supervisor are left as `unlinked`/workload scope. Behavior the sensor did not see is not reconstructed into a session assignment.

`/proc/<pid>/stat` start ticks are the process creation time, and they are not assumed to share unit, clock, or meaning with the Tetragon process_start/exec time. The PID namespace/start ticks are used to confirm the same process between supervisor and node. The kernel exec link checks the live process's exec/parent history, fixed command, and the interval from creation to bootstrap wait together, and is not confirmed by a single timestamp. The clock conversion and exec boundary are fixed in Q0, and if they cannot be separated the worker gate is set to failed.

**Two kinds of linkage:** linked in KernelSessionAttribution is the determination of which session's worker performed a kernel event. action/attempt Correlation.confirmed still requires a unique socket match from the existing AdapterObservation. When the supervisor relays worker requests, the kernel actor of the Pod→gateway connection is the shared supervisor, so that connection is not confirmed to a specific session/attempt from the IPC session context alone. The source original is not modified, and the two derived results are shown separately.

**Separating required and hardening:** Dedicated worker creation, the required bootstrap settings, worker observation/session linkage, and the task gate test are `core`, and failure means the MVP is incomplete. Adversarial file isolation hardening via Landlock, a different UID, or a separate container/sandbox is a separate profile. Unverified hardening states `not_run/unsupported` and that file isolation is not guaranteed, and the default worker gate is not downgraded to an optional feature. This is also independent of the optional `startup_guard_gate` before the container's first program.

Sources: [Python subprocess](https://docs.python.org/3.12/library/subprocess.html), [Tetragon process API](https://tetragon.io/docs/reference/grpc-api/), [Linux seccomp filter](https://docs.kernel.org/userspace-api/seccomp_filter.html). Support status and actual rejection results are recorded separately as GKE Q0/fixture evidence.

<a id="short-lived-pod-start-lifecycle-and-loss-contract-ref"></a>

## Short-lived Pod start, lifecycle, and loss contract

This contract is an implementation requirement for [TASK-01](TASK-01-gke-platform.md), [TASK-09](TASK-09-node-sensor.md), [TASK-10](TASK-10-correlation-health.md), and [TASK-16](TASK-16-delivery-runbooks.md). It is not a vendor default feature or a current GKE verification result. Unsupported observation, hook, and metadata delays are based on [Runtime Hooks](https://tetragon.io/docs/concepts/runtime-hooks/), watch history recovery on the [Kubernetes API](https://kubernetes.io/docs/reference/using-api/api-concepts/), and Collector durability limits on [OTel resiliency](https://opentelemetry.io/docs/collector/resiliency/). The start permit, WAL, and lifecycle contract are implemented separately by this project.

### Scope: MVP required and `startup_guard_gate`

| Category | Content | Install stage (TASK-16) | On failure |
| --- | --- | --- | --- |
| MVP required | Task start after node/Pod readiness and session permission/budget check, and control of multiple sessions, restarts, and failures. Long-lived Pod observation, and short-lived Pod filter readiness, lifecycle, ObservationGap, and 30-day retention | 4a: observation infrastructure, 5-6: health API and runtime task start gate | MVP incomplete |
| `startup_guard_gate` | Start guarantee before first code execution: start permit consumption, runtime guard, native start wrapping | 4b: runtime guard and start coordinator | The node/runtime is recorded as `startup_capture=unsupported`, and deployment is held only for short-lived Pod profiles that need the guard. It does not block installation, testing, or completion judgment of other features |

For combinations with `startup_capture=unsupported`, short-lived Pods are included in the MVP report in "observable scope and gap reporting" mode. This mode performs create-stage filter readiness, lifecycle recording, and ObservationGap, and does not claim to guarantee observation before first code execution. The plan's criterion "if either of the two features, kernel observation and policy improvement, is incomplete, the MVP is incomplete" is kept, and the start guarantee gate is reported as a separate judgment.

### Lifecycle records

- Runtime preparation and start/exit records and Kubernetes LIST/WATCH records are stored as separate sources. At create time, the lifecycle recorder records the cgroupsPath, cgroup inode, full container_id, `image_id`, and `image_manifest_digest`. Tetragon events are linked to these records by container_id.
- Even after Pod deletion or name/PID reuse, facts and tombstones per UID, boot, and container are kept for at least the retention period of the related kernel source data (initially 30 days). Pending joins are re-evaluated for at least 10 minutes after termination, and afterward the source data and mappings are still kept so they can be relinked with late evidence. The system does not assume that a Pod it failed to register can be restored from a current query.
- Unapproved ephemeral containers and runtime path bypasses are denied by Admission/RBAC. Bootstrap exceptions are allowed only for approved identities, images, and node roles needed for recovery, such as the sensor, recorder, and coordinator, and the list, changes, and observation exclusion scope are audited.
- Observed fixture Jobs are set to `restartPolicy: Never` and `backoffLimit: 0`. This is because the kubelet recreates a container that failed to start with a new container_id.

<a id="export-and-durability-boundaries-ref"></a>

### export and durability boundaries

- Tetragon export is fixed to JSON file export with an inode/offset checkpoint, and the rotation limit is set to match the measured peak rate. The interval lost to upstream rotation while the exporter was stopped is recorded as a gap with `stage = kernel_sensor_export` and `reason = EXPORT_ROTATION_LOSS`.
- The exporter's sequence is assigned in the normalization and spool stage of events the exporter has received. A kernel drop before that point cannot be proven by a sequence gap alone. Buffer/queue drops, policy exclusions, export limits, missing metadata linkage, and durable acks are recorded per stage. `source_epoch` distinguishes producer restarts, and on retransmission the original ID/epoch/sequence is kept.
- Completion of append and fsync to the local WAL/spool is the first local durability boundary, and an independent DB COMMIT ack is the next boundary against node loss. Loss between kernel and WAL and forced node loss before ack are outside the scope of the recovery guarantee. For an unrecoverable sequence interval, the producer sends `sequence_range_abandoned(range, reason, digest)`, and the server stores it as an ObservationGap and then advances the watermark. Unacked records are not silently discarded due to file rotation or a full queue.

### Node lifecycle and drain

- exec-pool and control-pool are configured to avoid unannounced recreation caused by node auto-upgrade and auto-repair. TASK-01 confirms and documents, using the official documentation, the configurable range of the release channel, maintenance exclusion, and auto-repair.
- Both exec-pool and control-pool have the startup taint `agentarium.io/observe-not-ready=true:NoSchedule`. The node readiness controller (`services/node-readiness/`, owned by TASK-01, running in `agent-control`) removes it only on nodes that pass the Q0 probe and whose TASK-10 lease is healthy. The sensor DaemonSet and bootstrap roles (agent-control, agent-observe, agent-release, agent-targets, agent-sensors) tolerate the control-pool taint. agent-adapters is blocked by VAP CEL from tolerating this taint so that it is placed only after observation is ready. For node-readiness's changes to nodes, VAP allows only the observe-not-ready entry of `spec.taints` (TASK-01).
- Because both pools have the startup taint, GKE-managed components (kube-dns, metrics-server, and so on) are placed in a separate `system-pool`. This pool has the taint `components.gke.io/gke-managed-components=true:NoSchedule` and is not observed. Pods in role Namespaces are not placed in this pool (TASK-01 3.5).
- Planned maintenance is operated as a manual procedure in the order cordon → hold → spool/ack check → drain. The spool/ack check covers the spool of the kernel event exporter and the WAL of the network policy log collector. The initial drain limit is 60 seconds. Drain does not evict DaemonSet Pods, and GKE surge upgrades respect PDBs for at most 1 hour and then forcibly evict the remaining Pods ([GKE node pool upgrade strategies](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/node-pool-upgrade-strategies)). Therefore, forced node loss is handled as an unrecoverable gap/unknown after the last ack.
- The success of preStop or a Pod finalizer is not used as a basis for crash recovery. There is also no guarantee that code already running is automatically terminated by a health hold.
- Required gaps are propagated to health holds and the timeline. Even if future execution resumes after recovery, past unrecovered gaps are kept. The event observation rate for short Pods, the Pod linkage rate, the session linkage rate, and node-loss gaps are reported with separate denominators.

<a id="execution-start-guarantee-contract-ref"></a>

## Execution start guarantee contract

This section is the contract of `startup_guard_gate`. The goal is **to confirm observation readiness and a durable start intent before the first user program of an observed target runs, and to refuse execution if this cannot be confirmed**. The same contract applies to init/main/sidecar containers and restarts. Trusted nodes, runtimes, and sensors are assumed, and it does not mean lossless capture of all events after start or exactly-once kernel execution. This gate is turned on only for node/runtime combinations that passed Q0, and there is currently no installation evidence.

### Confirmed vendor facts and their consequences

| Fact | Basis | Design consequence |
| --- | --- | --- |
| In NRI `startContainer`, if the plugin error is an `isFatalError` (ttrpc `ErrClosed`, `ErrServerClosed`, `ErrProtocol`, `context.DeadlineExceeded`), the plugin is closed and `nil, nil` is returned, so the container start proceeds (fail-open). The default `plugin_request_timeout` is 2 seconds | [containerd/nri `pkg/adaptation/plugin.go`](https://github.com/containerd/nri/blob/main/pkg/adaptation/plugin.go) (`startContainer`, `isFatalError`) | If the guard crashes or exceeds the time limit, the start is allowed. The guard must return an explicit non-fatal error before the deadline, and after-the-fact detection (`start_guard_bypass_detected`) is required |
| The GKE containerd user configuration documentation supports three items: `privateRegistryAccessConfig`, `registryHosts`, and `writableCgroups`. Enabling NRI or adding a runtime handler is not among the supported settings | [GKE containerd configuration](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/customize-containerd-configuration) | Installing NRI and a handler means changing node configuration with something like a privileged DaemonSet, which is outside GKE's supported scope and disappears when nodes are recreated or upgraded. Q0 tests whether it persists after recreation and upgrade, and if it does not, it is left as `unsupported` |

### Q0 required verification items

| Item | Criterion |
| --- | --- |
| When `required_plugins` is verified | The owner of the relevant Task rechecks, using containerd `docs/NRI.md`, the review finding that it is verified only at the create stage. A path where the plugin is closed between create and start is a required fault-injection item |
| Plugin closure and timeout injection | Measure whether the start is allowed under guard kill, socket disconnection, and deadline exceeded, and whether `start_guard_bypass_detected` and a workload hold are produced |
| Concurrent starts | Because NRI serializes plugin calls with a global lock, the number of concurrent starts per node and the p95 start latency (100 or more samples) are used as metrics |
| Node recreation and upgrade | Check whether node configuration changes disappear and whether the startup taint is reapplied on nodes where they disappeared |
| Image binding | Method for comparing the `image_id` (config digest) exposed by CRI/OCI with the `image_manifest_digest` checked by Admission |
| Basis that the first code did not run | [First-code-not-run decision](#first-code-non-execution-judgment) below |

### Enforcement points and defense against omissions

Tetragon's filter mapping is prepared at the container create stage and checked again on the actual OCI start path. Create success alone does not allow the subsequent start. The trusted runtime handler/guard must check whether the required guard is applied to the OCI spec to be created and to the actual instance to be started, and must reject a missing installation, digest mismatch, wrong handler, or unavailable bridge/socket. Because fatal NRI errors are fail-open, returning a hook failure alone is not considered a defense against omissions. If an exec is observed without a consumed start permit, TASK-10 issues `start_guard_bypass_detected` and holds that workload with a `bypass_detected` hold.

- runtimeClass: TASK-01 Admission allows a single allowlisted entry (`agentarium-guarded`) only if Q0 passed and denies everything else. If Q0 fails, specifying a runtimeClass continues to be denied. The fact that a runtimeClass name was specified is not evidence that the actual handler is enforced.
- Pod annotations related to required plugins (such as tolerate missing) are prohibited by Admission.
- Because the OCI `startContainer` hook runs in the container namespace, it is not connected in a way that exposes the host bridge's credentials or management socket to the workload. Kubernetes `PostStart` has no guaranteed execution order relative to ENTRYPOINT, so it is not a substitute for this guard. [OCI lifecycle](https://github.com/opencontainers/runtime-spec/blob/main/runtime.md), [OCI hooks](https://github.com/opencontainers/runtime-spec/blob/main/config.md#startcontainer-hooks), [Kubernetes lifecycle hooks](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/)
- The node runtime bridge's certificate is issued by `/internal/workload-certificates` bound to the node/boot. The bootID has a trust limitation in that it is a value self-reported by the kubelet.

### Start order and state evidence

1. Read the execution binding from the trusted runtime and compare it against the coordinator's placement registration values. After installing the filter and confirming local health, COMMIT the preparation lifecycle fact to the independent DB.
2. The server issues a StartAttempt for the same binding and a 10-second start permit. The bridge rechecks with a new local snapshot and consumes the permit once. The consumption state, audit event, and outbox are COMMITted in one DB transaction.
3. COMMIT the `start_requested` intent to the independent DB and append/fsync it to the node-local guard journal. An unknown ack or an fsync failure does not allow the start and returns a non-fatal error. The final local check re-confirms the permit validity period, guard deadline, generation, filter, spool, and hold.
4. The guard only returns allow (nil) as the NRI `StartContainer` response. The actual start is performed by containerd with `task.Start`, and the guard does not call the native start directly. The evidence for `runtime_start_returned` is NRI `PostStartContainer` or the `started_at` of the CRI container status. The actual start/exit is reinforced by comparing sensor exec/exit with the runtime history. Observation of the first code is not confirmed from `consumed`, `start_requested`, or a successful runtime response alone.

The state progresses as `prepared → issued → consumed → start_requested → runtime_start_returned`. `start_observed` from actual exec evidence and the exit fact are an independent observation axis and can arrive before the return record. A request failure or a definitive pre-start rejection is recorded as `start_failed`, and a crash or lost response for which execution cannot be determined is recorded as `start_unknown`. Because the kubelet can recreate a failed container with a new container_id, `start_unknown` places a `start_unknown` hold at the Pod/workload level. Even if a terminated process disappears from the runtime query, it is not changed to not-executed. Detailed state reconciliation follows [TASK-10](TASK-10-correlation-health.md#35-startup-state-identity-and-retry-implementation).

### First-code non-execution judgment

The entrypoint of the fixture image sends a marker to an external marker server as its first action. "First code not executed" is judged only when the guard journal's rejection record, the absence of CRI `StartedAt`, and the absence of the marker are seen together. Because the containerd history comes from the same runtime as the guard, it is not an independent source, and the report states the limitation that the absence of the marker must be distinguished from a network failure. If the evidence is insufficient, the result is unknown, and this judgment affects only `startup_guard_gate`.

### Identity, time, and concurrency

The binding is a version-pinned normalized digest of `cluster_uid/pod_uid/container_id/container_name/restart_instance/image_manifest_digest/image_id/node_uid/boot_id/runtime_profile_digest`. The bridge identity is obtained from the authentication context and bound to the registered node/boot. Claims about node/generation/image in the body are not trusted as-is. The workload cannot access the start management socket, API, DB, or guard configuration.

The time limits are split into two.

| Limit | Reference clock | Value | Meaning |
| --- | --- | --- | --- |
| start permit TTL | Server DB (`statement_timestamp()`) | 10 seconds | Validity period from issuance to consumption |
| NRI path guard deadline | bridge monotonic clock | Smaller than `plugin_request_timeout`. Starting value 1.5 seconds under the default 2-second setting | The entire check, consumption, journal fsync, and final check that must finish within one NRI request. If the remaining time is insufficient, reject with a `STARTUP_GUARD_UNAVAILABLE` non-fatal error before the deadline |

The guard deadline is not reset on each retry. A long image pull/create is a separate preparation stage and is not measured as if it were included in this time. A clock skew of 2 seconds is not an expiry grace period, and unknown time trust or a reboot is a condition for discarding old permits. If `PostStartContainer` or CRI `started_at` does not arrive after allow (nil) is returned, execution is investigated as unknown and not retried automatically. If a host handler approach rather than the NRI path is chosen in Q0, the timeout for that path is redefined by the same principle (a deadline smaller than the upper timeout, explicit non-fatal rejection).

Planned sensor/rule reloads and guard updates share a node-local RW lock and a generation fence. The start path holds the shared lock from the current check until the guard returns allow (nil), and the reload path uses the exclusive lock in the order: block new starts → complete or mark unknown the in-progress starts → update the generation and discard old permits → reload/probe. It is not claimed that a distributed DB lock alone prevents local reloads. Unplanned sensor kills, node crashes, and kernel drops cannot be prevented by this lock and are handled by immediately available local blocking and TASK-10's gap/follow-up hold. The times of last check → allow return → containerd `task.Start` → first exec → WAL/DB ack are each measured, and the remaining failure races are shown in the results.

<a id="result-recording-contract-ref"></a>

## Result recording contract

Planned path: `evidence/gcp/runs/<run_id>/`. Functional measurement has not been run yet, so no measured values are generated. The originals are stored in a private GCP repository, and only sanitized manifests/summaries/hashes and safe references are stored in Git. `status` uses the [report status](#enum-definitions) enum.

```json
{
  "task_id": "TASK-04", "status": "not_run",
  "implementation_commit": null, "image_digest": null,
  "environment_manifest": null, "policy_bundle_id": null, "policy_epoch": null,
  "run_id": null, "run_kind": null, "fixture_set_digest": null,
  "baseline_bundle_digest": null, "candidate_digest": null,
  "expected_cases": null, "observed_cases": null,
  "passed": null, "failed": null, "unknown": null,
  "metrics": null, "invariants": null, "release_eligible": null,
  "startup_capture": null,
  "evidence_refs": [], "limitations": ["실제 기능 시험 없음"]
}
```

After implementation, each run leaves `manifest.json, expected.json, observed.jsonl, summary.json, report.md` and approval/deployment/recovery references. The manifest includes the project/cluster, runtime/kernel, sensor/hooks, app/OPA/policy/catalog, clock, repetition count, and `fixture_set_digest`. Ratio metrics store the numerator, denominator, and 95% interval together, and a p95 with fewer than 100 samples is set to null with `insufficient_sample = true`. Values that were not measured are null and are not changed to 0.

## Appendix A. policy data and patch schema

### policy data layout

The bundle's `data` has only the keys below. Go `packages/bundles` (TASK-14) builds it by combining the catalog YAML (TASK-02) and the policy data.

| data path | Shape | Source |
| --- | --- | --- |
| `data.catalog` | `{catalog_digest, operations: {<operation_id>: CatalogOperation}, targets: {<target_id>: CatalogTarget}}` | TASK-02 catalog YAML |
| `data.receiver.allowed_disclosure_fields` | String array (sorted, no duplicates) | Policy data |
| `data.standing_rules` | `{<standing_rule_id>: StandingRule}` (map keyed by id) | Policy data |
| `data.service_profiles` | `{<profile>: {operation_ids[], model_profiles[], target_ids[]}}` | TASK-03 service profile table. Not a patch target |
| `data.adapter_constraints` | `{<adapter_id>: {max_request_bytes, max_response_bytes, allowed_route_ids[]}}` | Policy data |
| `data.sensor_rules` | `{<rule_name>: {selector, enabled}}` | Written by the operator |
| `data.data_class_rank` | `{"none": 0, "synthetic": 1, "internal": 2, "confidential": 3}` | Fixed |

Initial `data.standing_rules` (source of truth):

```json
{
  "standing.k8s_read.v1": {
    "standing_rule_id": "standing.k8s_read.v1", "session_kind": "user", "profile": null,
    "operation_ids": ["k8s.pods.list", "k8s.events.list", "k8s.pods.logs"],
    "target_pattern": "k8s-agent-targets", "limits": {"limit": 100, "tailLines": 200, "limitBytes": 65536},
    "data_profile": "synthetic", "session_budget": 100
  },
  "standing.model_synthetic.v1": {
    "standing_rule_id": "standing.model_synthetic.v1", "session_kind": "user", "profile": "agent",
    "operation_ids": ["model.generate"], "target_pattern": "agent-platform-gemini",
    "limits": {"request_bytes": 65536}, "data_profile": "synthetic", "session_budget": 50
  },
  "probe.activation.v1": {
    "standing_rule_id": "probe.activation.v1", "session_kind": "service", "profile": "activation_probe",
    "operation_ids": ["receiver.submit"], "target_pattern": "receiver-probe",
    "disclosure_fields": ["summary"], "limits": {"request_bytes": 4096},
    "data_profile": "synthetic", "session_budget": 4
  }
}
```

StandingRule uses the `operation_ids[]` array. `probe.activation.v1` holds only when `control_health.activation_probe.action_id` equals the request's `action_id`, and it cannot be a patch target. `receiver-probe` is the receiver target in the probe namespace.
### patch structure

```json
{
  "kind": "receiver.allowed_disclosure_fields",
  "ops": [
    {"op": "replace", "path": "/receiver/allowed_disclosure_fields", "value": ["summary"]}
  ]
}
```

- `ops` has 1 to 10 entries and uses only RFC 6902 `add`, `remove`, and `replace`. `path` must be within the JSON Pointer prefixes allowed for the kind. Go `packages/bundles` applies the patch and, after applying it, rechecks the entire data against the corresponding JSON Schema.

| kind | Allowed path prefix | value schema |
| --- | --- | --- |
| `receiver.allowed_disclosure_fields` | `/receiver/allowed_disclosure_fields` | A full replace is an array of field name enums from the receiver payload schema (1 to 16, no duplicates). `/-` add and `/<index>` remove take that enum string |
| `targets` | `/catalog/targets/<existing target_id>/operation_ids`, `/allowed_cidrs`, `/max_data_class` | Respectively a catalog operation_id array, a CIDR string array, and a `data_class` enum. Adding a new target is a catalog change (TASK-02) and is not done with this kind |
| `standing_rules` | `/standing_rules/<standing_rule_id>` (whole), `/standing_rules/<id>/limits`, `/target_pattern`, `/data_profile`, `/session_budget` | StandingRule JSON Schema (TASK-04). Excludes `probe.activation.v1` |
| `adapter_constraints` | `/adapter_constraints/<adapter_id>/max_request_bytes`, `/max_response_bytes`, `/allowed_route_ids` | Integer (1 to 1048576), integer, catalog route_id array |
| `policy.draft.create` | `/standing_rules/<existing id>/operation_ids` (element remove), `/standing_rules/<existing id>/limits/<key>` (replace with a smaller value), `/catalog/targets/<id>/operation_ids` (element remove) | Only narrowing is allowed. add and value increases are rejected. Excludes `probe.activation.v1` |
| `sensor_rules` | `/sensor_rules/<rule_name>` | TASK-09 selector schema. Only via `operator_patch` |

**`policy.draft.create` builder:** The input is `{window_start, window_end, operation_ids[]}`. This kind only narrows. (1) Select allow decisions within the window (`decision_basis = standing_rule`) and their `decision_inputs` and `action_results`. (2) For each standing rule, compute the operations and targets actually used and the observed maximum per `limits` key. (3) Build ops that remove operations unused during the window from `operation_ids`, remove operations unused by a target from `catalog.targets[].operation_ids`, and lower `limits` to the observed maximum. (4) If the result has even one item with `permission_widening.widened = true`, the candidate is set to `rejected`. Adding approval-based actions as a new standing rule is a permission widening that removes human approval, so it is outside the MVP scope. The model only attaches descriptions to this result.

## Appendix B. model.generate integration contract

This section decides the undecided integration items of #154 and #260. TASK-02's typed schema and content digest are kept. The affected Tasks are 02, 03, 04, 05, 12, 15, and 16. Adoption of this section is not evidence that implementation, deployment, or Gemini E2E is complete.

### ClientAction and conversation

`requested_target` is `{target_id, profile}`. `arguments` has `conversation_id`, `messages`, and `tool_declarations`. Only `policy_proposal` adds `phase=exploration|final`, and it is required there. Other profiles do not allow the `phase` key at all. The client does not override generation settings or the response schema. Each message has all of TASK-02's `kind, role, source, text, ref, function_name` fields, and fields that do not apply are `null`.

- text: set only `kind=text`, `role=user`, `source=system|user`, and `text`.
- Previous model turn: set `kind=model_turn`, `role=model`, and `ref={ref:model_turn, action_id:null, turn_index:<integer>}`. The caller does not send the original text or the thought signature. The adapter inserts the stored raw parts at the specified position. It does not automatically append every turn of the conversation.
- Tool result: set `kind=tool_result`, `role=user`, `source=tool_result`, `function_name`, and `ref={ref:action_result, action_id:<uuid>, turn_index:null}`. The result body is not resubmitted.
- The conversation ID for `agent` must equal the user session ID held by the supervisor. A service profile's conversation belongs to that service session. References to a different tenant, session kind, or session ID, expired references, and results that do not match a tool call are rejected before sending.

### Installation input and tool declarations

TASK-16 `model` has the common `model_id`, `model_region`, and `api_version`, plus `profiles` and `tools`. The exact four keys of `profiles` are `agent`, `policy_proposal`, `intent_check`, and `discovery`. The value fields follow the existing `canonical.ParseModelProfiles`: `max_output_tokens`, `max_request_bytes`, `generation_config`, and `response_schema`. Request limits and timeouts cannot exceed the TASK-05 table. The source of truth for the output limit is `max_output_tokens`, and if the generation config has `maxOutputTokens`, it must be equal.

- The TASK-16 renderer produces `model-profiles.json` and `model-tools.json` from the same lock, creates immutable ConfigMap copies with the same digest in each consumer namespace, and mounts them read-only into the Gateway and the model adapter. The digests of both files are recorded together in the deployment record. Each process validates the files and records the digests at startup. Proposer and Discovery are also given the same read-only ConfigMap. For the agent runtime, the same `model-tools.json` is included at a read-only path in the approved image and is checked against the ConfigMap digest at build/deploy time. The worker reads the agent array from this installed file and uses it unchanged for the ADK declarations and the ClientAction. The volume allowance of the existing agent-exec is not extended. Consistency across instances is checked by renderer/deployment validation.
- `tools` also has the same four profile keys, and each value is an array of `{name, description, parameters}` declarations. `parameters` follows the TASK-02 JSON Schema restrictions. The order of declarations is also part of the digest.
- agent: only the three TASK-15 declarations `submit_action`, `poll_action`, and `request_approval` are registered. The worker submits this array. The Gateway and the adapter check that the digest of the submitted declarations equals the JCS SHA-256 of the registered array. The adapter restores the request from the registered original. Therefore the content storage format and the content digest do not change. This does not mean arbitrary sets of 8 tools are supported.
- policy_proposal: three tools, `get_action_evidence`, `get_policy_bundle`, and `get_regression_report`. They correspond to the existing `evidence.action.read`, `evidence.bundle.read`, and `evidence.regression.read` operations respectively.
- discovery: two tools, `discovery_source_read` and `discovery_callgraph_read`. They correspond to the existing `discovery.source.read` and `discovery.callgraph.read` respectively.
- intent_check: an empty array. Callers of the three service profiles submit `tool_declarations=[]`, and the adapter injects the fixed tools. Unregistered function names are not executed.
- Model and generation settings not yet decided in Q0, missing schemas/tools, incorrect limits across profiles, and digest mismatches cause installation or preflight to fail. The agent schema allows `null`. Other profiles use the existing fixed output schema, and phase selection for policy_proposal follows the next section. Combined use of Gemini tool calling and a response schema must be confirmed in Q0 with the selected model, and schema validation is not turned off to avoid failures.

`thinkingConfig` and temperature are placed inside each profile's `generation_config`. The source of truth for model ID/location/API version is the lock, and the renderer checks that they match the project/location/model_id of the catalog model target and the API version of the generateContent route. On mismatch, installation is rejected, and the lock is not overwritten with catalog values. The same comparison is performed later in the TASK-14 bundle release, and the adapter rejects mismatching model targets/routes at bundle activation.

The `tool_declarations_digest` recorded in the Proposer's PolicyProposal is the JCS SHA-256 of the installed policy_proposal declaration array. It is distinct from the empty-array digest of a service ClientAction. At startup, the Proposer checks that the installed array equals its own versioned prompt declaration array. The origin of the tools actually sent to the model is traced through the installation digest and wire_body_digest.

### Proposer generation phase

Following the #271 owner decision, the `policy_proposal` phase is included in the canonical content and bound by the content digest. `exploration` uses the three registered evidence tools and does not send a response schema/MIME type. `final` does not send tools and uses the installed JSON response schema/MIME type. A functionCall in final is rejected. Both phases use the installation input for the generation config and request/token limits. Whether a schema is used depending on the phase is also reflected in response_schema_digest (null for exploration, the installed schema digest for final). The client cannot submit an arbitrary schema/config. A schema-fix retry stays in final. The history of a final request retains the functionCall/functionResponse of the previous phase. This history is validated against the installed profile tool names, and Q0 checks whether a Gemini request that sends only a schema without tools in this turn succeeds. The Q0 for combined tools/schema use in discovery is separate.

### DB reference reads

`model_turns` stores `tenant`, `session_kind=user|service`, `session_key`, and `action_id`. `expires_at` is the retention upper bound used for deletion: a user session uses `max_expires_at`, and a service session uses its actual `expires_at`. Read permission separately checks the current session's state and refreshed `expires_at`. Therefore a validly refreshed user session continues to use its previous turns, while a revoked or expired session cannot access the raw text even while it is retained. The profile TTL added to the response receipt time is not used as a substitute. raw parts SELECT is restricted to the model-only role.

- The `decisions.model_action_context` view exposes only `action_id, tenant, session_kind, session_id, expires_at, retain_until` of `model.generate` actions. `expires_at` is the current expiry time of the corresponding user/service session, and `retain_until` is the user's `max_expires_at` or the service's `expires_at`. Revoked or expired sessions are not returned. SELECT is granted to `adapter_model_reader`, and SELECT on identity/gateway base tables is not granted.
- Only the model-only reader can EXECUTE `adapter.read_model_action_result(request_action_id uuid, referenced_action_id uuid)`. The function checks that the requesting action exists in the context above and that the tenant, session kind, and session ID of the referenced action are all the same. If they match, it returns only `action_id, execution_state, truncated, result_body` of the last completed result. If none exists or the scope differs, it returns 0 rows. Only the function owner reads the required base tables, and the search_path of the SECURITY DEFINER function is fixed. PUBLIC EXECUTE is revoked. SELECT on the restricted identity session view is granted only to the NOLOGIN owner of the context view. The function owner has only the SELECT needed for the action scope in decisions and the sanitized results in adapter, and no raw model turn permission is added to the runtime/Gateway roles.
- The adapter does not use the session ID in the caller's body as the basis for DB read permission. It uses the ID of the stored current model action. Model turn reads also match the current action context against the three scopes of the stored turn. If the read fails, there is no fallback to a direct provider call or to a read of another session.

### Completion evidence

The three paths are verified separately: Discovery's Gemini → snapshot read → follow-up turn, the Proposer's Gemini → evidence read → policy-diff candidate, and the agent's ADK → IPC → Gateway → Gemini → typed tool → follow-up turn. Local fake transport tests are reported as wire/state verification. Live completion requires the actual Gateway/adapter action IDs, the Gemini response, references to tool results in the same session, and evidence that direct egress is blocked. The Proposer's result is a candidate and is not deployed without human approval.

## Appendix C. Governance Checklist

The level that Agentarium's controls must meet is fixed as checklist items. The regression tests (TASK-13) use these IDs as the tracing key in fixtures' `governance_refs[]` and in the report's `governance_summary[]`, and the policy change approval screen (TASK-14 3.1) shows the `governance_summary` of the `candidate_final` report. Proposal generation (TASK-12) does not use these IDs. Only IDs from this table go into `governance_refs[]` and `governance_summary[].governance_id`.

- **This is not a compliance determination.** The basis column is a reference mapping for tracing the source of each requirement, and the article numbers have not been checked against the original texts. Neither the applicable party, whether the system is high-risk AI, nor extraterritorial applicability has been determined. This is not legal advice.
- **These are not implementation or verification results.** "Corresponding Task" is the location of the specification that defines the control, and the implementation and verification status of every item is `planned / not_run`.
- **Scope:** The general information processing system items (G-01–G-27) are the scope of this proof of concept. The personal data items (P-01–P-15) are a follow-up scope added when an adapter that handles personal data is added, and they presuppose all general items. Financial regulation and domestic law are not covered.
- **Notation in the Corresponding Task column:** "Partial" means the specification covers only part of the item, and the missing part is noted alongside. "None (out of scope)" means it is intentionally not covered in this proof of concept. "None (follow-up needed)" means it is needed within scope or in the follow-up scope, but no corresponding specification exists yet.
- **Source check column:** Records whether the basis article was checked against the original text, as `미대조` (not checked) or `대조함(날짜)` (checked, with date). Currently all are `미대조`. Submission materials cite article numbers only for items marked `대조함`, and for the rest only the name of the standard (the submission contract in [TASK-16](TASK-16-delivery-runbooks.md)).
- **Verification evidence column:** Records the fixture ID that actually performs the "verification method" (linked through `governance_refs[]` in [TASK-13](TASK-13-regression-harness.md)) or the test row in a Task document. Before execution, only the planned links are recorded. Execution results (`run_id`, per-case results, evidence references) are kept in the RegressionReport, not in this table. Fixtures marked `(measurement)` are not included in the `candidate_final` run and therefore do not appear in the `governance_summary` at policy change approval. "Unlinked" means no fixture is linked.
- **Source of the IDs:** Currently the two tables below are the only definition of the IDs. During implementation, the machine-readable source `tests/regression/governance_ids.json` (`[{id, scope(general/personal_data)}]`) will be generated from these tables; this file does not yet exist in the repository. After the file exists, the `fixture_registry` check (TASK-13) validates `governance_refs[]` against this file, and the document checker (TASK-16) checks that the set of IDs in this file equals the set of IDs in the two tables below. The report records `governance_map_digest` so that runs whose fixture-to-ID links changed can be distinguished (RegressionReport).

| Standard | Use | Original text |
| --- | --- | --- |
| EU AI Act (Regulation (EU) 2024/1689) | Articles 12, 14, and 15 are requirements for high-risk uses and are used here only as a design baseline. Article 26 (record keeping) and Article 50 (AI disclosure) are also reference mappings | [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) |
| NIS2 (Directive (EU) 2022/2555) | Applies only when the operating organization is a covered entity. Article 21 (risk management measures) and Article 23 (incident reporting) are used as references | [EUR-Lex](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) |
| GDPR (Regulation (EU) 2016/679) | Reference mapping for the personal data items (P) | [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2016/679/oj) |
| CIS GKE Benchmark | Baseline for cluster settings that the user can change. The version to use and the checking tool have not been decided | [CIS Benchmarks guide for GKE](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/cis-benchmarks) |

### General information processing system items (G)

| ID | Check item | Basis (reference mapping) | Original text check | Corresponding Task | Verification method | Verification evidence |
| --- | --- | --- | --- | --- | --- | --- |
| G-01 | Decisions and rejections of agent requests are traced according to defined recording rules | AI Act Art. 12, NIS2 Art. 21 | Not checked | [TASK-04](TASK-04-policy-gateway.md), [TASK-07](TASK-07-audit-store.md), [Recording of normalization-stage rejections and evaluation failures](#policy-decision-contract). Authentication failures leave only rate limit logs; rejections before the envelope are distinguished as `request_rejected`, evaluation failures as `policy_evaluation_failed`, and decisions as `policy_decided` | Compare event presence and whether an action or decision is created for normal decisions and for each rejection stage | Tests in chapter 7 of [TASK-04](TASK-04-policy-gateway.md) recording pre-envelope rejection, normalize, and evaluation failure. fixture not connected |
| G-02 | Records are stored outside the execution area and cannot be modified or deleted from the execution area | AI Act Art. 12 and 15 | Not checked | [TASK-07](TASK-07-audit-store.md), [TASK-06](TASK-06-egress-credentials.md). Partial: the scope claimed as external evidence goes only as far as "tampering is detectable", and deletion or tampering by a principal with administrator privileges cannot be prevented (TASK-07 chapter 1) | Attempt to modify or delete records from the execution Pod and from control roles without record write permission, and confirm that the attempts are rejected | `audit-record-tamper-denied`, permission and retention tests in chapter 7 of [TASK-07](TASK-07-audit-store.md) |
| G-03 | Records are retained for a defined period | AI Act Art. 26 | Not checked | [TASK-07](TASK-07-audit-store.md). The per-store retention table defines 30 days for evidence, decision-input export, Cloud SQL originals, and Cloud Logging, and 90 days for the summary bucket and Cloud SQL summaries, along with the deleting principal and whether it is locked. The retention policy starts unlocked. Partial: there is a review opinion (before the original text check) that the basis article requires retention of at least 6 months, and this falls short of that baseline. Whether to adopt the 6-month baseline has not been decided. Extending the retention period also extends the deletion target period of P-10, so this assumes P-09, under which raw personal information is not put into retained records and is stored separately | Confirm the retention period setting and the rejection of deletion within the period, and record the difference between the baseline and the current value in the report | Retention, DB retention, and log retention tests in chapter 7 of [TASK-07](TASK-07-audit-store.md). fixture not connected |
| G-04 | Missing records, delays, and collection failures are detected and marked as gaps. Undetected losses may remain | NIS2 Art. 21 | Not checked | [TASK-10](TASK-10-correlation-health.md), ObservationGap | Deliberately stop a sensor or collector and confirm that a gap is displayed | `sensor-gap-hold`, `kernel-spool-replay`, `kernel-spool-pressure`, `network-finding-unmatched-deny` (measurement), `network-finding-log-outage` (measurement) |
| G-05 | For receiver sends, what was actually executed and what was recorded are compared using different sources | AI Act Art. 12 | Not checked | [TASK-08](TASK-08-destination-evidence.md), [TASK-10](TASK-10-correlation-health.md), [TASK-11](TASK-11-alignment-timeline.md). Partial: the only target whose effect can be confirmed by an independent source is the team-owned receiver. The `evidence_level` upper bound for Kubernetes reads and model calls is `accepted` | Inject an adapter defect that changes the sent content after passing preflight, and confirm that it is judged as a mismatch with the receiver's receipt record. Modification after approval is blocked first at preflight, so this path cannot be tested without defect injection | `adapter-post-preflight-mutation` (measurement) |
| G-06 | A request decided as `approval_required` is executed only after a human sees the target, disclosed information, count, and expiry and approves it | AI Act Art. 14 | Not checked | [TASK-03](TASK-03-identity-approval.md), [TASK-04](TASK-04-policy-gateway.md), [TASK-05](TASK-05-service-adapters.md). Requests allowed by a standing rule run without human approval | Modify a request after approval and confirm that it is rejected before sending | `receiver-content-mutation` |
| G-07 | When an anomaly is confirmed, subsequent execution is held, and a human can also hold subsequent execution and cancel the sessions within the scope | AI Act Art. 14 | Not checked | [Operator stop](#operator-stop), [TASK-10](TASK-10-correlation-health.md) `operator_stop`, [TASK-11](TASK-11-alignment-timeline.md). Holds and session cancellation do not terminate code in running Pods. Forced Pod termination is the TASK-16 break-glass procedure | Confirm identity and scope verification of the operator request, holding of new requests, cancellation of sessions and unused approvals, and that the cancelled state remains after release. Also confirm mismatch holds separately | `hold-session-scope`, operator stop tests of [TASK-10](TASK-10-correlation-health.md) |
| G-08 | The scope of permissions granted is displayed before approval, and AI assists by warning about differences from the scope the human understood | AI Act Art. 14 | Not checked | [Approval intent check](#approval-intent-check-intent-check), [TASK-04](TASK-04-policy-gateway.md). Partial: the warning is an assist feature, not a guarantee. If the model exceeds the time limit, it is `not_run` and processing proceeds with the deterministic decision only, without a warning | Inject an approval request broader than required and confirm that a warning is attached, and that a model timeout is displayed as `not_run` | `intent-divergent-email`, `intent-consistent-summary`, `intent-standing-rule-escalation`, `intent-prompt-injection`, `intent-model-timeout` |
| G-09 | AI output alone cannot create an allow, and widening proposed by AI is acknowledged item by item by a human | AI Act Art. 14 and 15 | Not checked | [AI one-way principle](#ai-one-way-principle), [Regression test contract](#regression-test-contract). `ai_created_allow_count = 0` is maintained, and AI-originated widening acknowledged by a human is reported separately as `ai_proposed_widening_count` | Confirm that direct verdict widening and unapproved activation are 0. Missing per-item acknowledgment of widening is rejected, and the separate count of approved AI-originated widening is confirmed | AI invariant tests in chapter 7 of [TASK-13](TASK-13-regression-harness.md), COMMON widening proposal and regression test rules. fixture not connected |
| G-10 | An agent that interacts with people or generates content discloses that it is AI | AI Act Art. 50 | Not checked | None (out of scope). The two initial tasks send only to team-owned test targets and do not interact directly with people. If an adapter that produces external output is added, a specification that checks the AI disclosure field at preflight is needed | Confirm that the agent's external output carries an AI disclosure | Not connected |
| G-11 | An agent cannot change the rules, sensors, or recording settings that control it | AI Act Art. 15, NIS2 Art. 21 | Not checked | The `sensor_policy` baseline and read-only drift probe permissions in chapter 4 of [TASK-01](TASK-01-gke-platform.md), periodic comparison in [TASK-10](TASK-10-correlation-health.md) | Confirm that changes to policies, labels, and sensors from the execution Pod are rejected and that the `sensor_policy` and `network_policy` digests are kept. Separately confirm that a baseline change by an authorized test principal is reported as drift | Change attempts from inside the execution Pod in chapter 7 of [TASK-01](TASK-01-gke-platform.md), [TASK-10](TASK-10-correlation-health.md) drift probe. fixture not connected |
| G-12 | An agent can send only registered service requests to the inspection path and cannot go directly to the outside | AI Act Art. 15, NIS2 Art. 21 | Not checked | The allow table and NetworkPolicy examples of [TASK-06](TASK-06-egress-credentials.md). The probe runner and start fixture also follow the gateway path, and no direct path to control-health is opened | Compare the allow table with the rendered result, and confirm that successful connections for source/destination pairs not in the allow table are 0 | `direct-egress-denied`, allow table match and logging configuration tests in chapter 7 of [TASK-06](TASK-06-egress-credentials.md) |
| G-13 | Access to internal segments (other Pods, control services, the cluster API, metadata) is blocked, and those attempts are observed | NIS2 Art. 21 | Not checked | [TASK-06 3.1](TASK-06-egress-credentials.md#31-network-allow-table-and-bootstrap) (blocking), [TASK-06 3.4](TASK-06-egress-credentials.md#34-network-policy-logging-configuration) (network layer records), [TASK-09](TASK-09-node-sensor.md) `tcp_connect`, [TASK-10 3.7](TASK-10-correlation-health.md#37-network-policy-records-and-composite-decisions) (`network_segment`, `boundary_crossing`). Partial: for a Service ClusterIP destination whose destination Namespace is not in the log and not in the lock either, the segment is classified only as `exec_to_internal_other`. All observation tests are in the measurement scope | Confirm that access attempts per internal target are blocked, and compare whether those attempts remain in `correlation.network_findings_latest` with the expected `network_segment` and `boundary_crossing` values. Because these attempts have no action, they are checked in the finding view, not in the action timeline | `direct-egress-denied`, `network-finding-blocked-attempt` (measurement), `network-finding-udp-dns` (measurement), `network-finding-exec-to-exec` (measurement) |
| G-14 | Established connections to destinations outside the allow table, process executions with a broken lineage, and write attempts to protected paths are judged as violation candidates and the workload is held; blocked connection attempts are kept as records | AI Act Art. 15 | Not checked | The risk event hold (`risk_event`) of [TASK-10 3.2](TASK-10-correlation-health.md#32-control-health-decision), [TASK-10 3.7](TASK-10-correlation-health.md#37-network-policy-records-and-composite-decisions) (NetworkFinding that distinguishes attempt, block, and establishment), [TASK-11](TASK-11-alignment-timeline.md). Partial: there is no process lineage baseline such as an allowed binary list, and the protected path is only one synthetic file | Confirm per decision rule. For an established unregistered connection, a protected path write open, and an exec with a broken lineage, check that a workload `risk_event` hold is created. For a blocked connection attempt, check that a `blocked_attempt` finding remains and no hold is created. When the evidence is insufficient, check that it remains `unknown` and is not asserted as a violation | `network-finding-blocked-attempt` (measurement), `network-finding-udp-dns` (measurement), `network-finding-unregistered-established` (measurement), `network-finding-unmatched-deny` (measurement), `network-finding-log-outage` (measurement), risk event hold tests in chapter 7 of [TASK-10](TASK-10-correlation-health.md) |
| G-15 | Instructions contained in external content or responses are not treated as commands | AI Act Art. 15 | Not checked | Response handling in the [Plan](../plan.md), [TASK-12](TASK-12-policy-proposals.md). General-purpose interpretation is out of scope | Inject a response containing instructions and confirm that policies and decisions do not change | `intent-prompt-injection` |
| G-16 | If control or observation is not ready or fails, new execution is not allowed | NIS2 Art. 21 | Not checked | [Task start contract](#agent-work-startup-contract), [TASK-10](TASK-10-correlation-health.md), [TASK-15](TASK-15-runtime-integration.md) | Stop the gateway, the sensor, and the storage each in turn and confirm that new requests are held | `sensor-gap-hold`, `audit-db-unavailable` |
| G-17 | Permissions are granted minimally per service, operation, target, and data scope | NIS2 Art. 21 | Not checked | [TASK-02](TASK-02-catalog-contracts.md), [TASK-04](TASK-04-policy-gateway.md) | Request a forbidden operation of the same service and a different target, and confirm that they are rejected | `target-scope-denied` |
| G-18 | Real credentials are not placed in the execution area | NIS2 Art. 21 | Not checked | [TASK-06](TASK-06-egress-credentials.md) | Search the files, environment variables, and metadata of the execution Pod and confirm that there are no secrets | Not connected |
| G-19 | The session and user that issued a request are verified so that they cannot be forged | NIS2 Art. 21 | Not checked | [TASK-03](TASK-03-identity-approval.md), [Session-dedicated worker contract](#session-dedicated-worker-contract). File and memory isolation between sessions in the same Pod is not guaranteed | Confirm that a request sent with a changed session identifier is rejected | `session-worker-registration` |
| G-20 | Cluster configuration follows a recognized security configuration benchmark | CIS GKE Benchmark | Not checked | [TASK-01](TASK-01-gke-platform.md). Partial: some settings such as private nodes, the node image, and Pod Security settings are pinned, but there is no tool or procedure that checks all user-responsibility items of the benchmark | Check the user-responsibility items of the benchmark with a checking tool | Not connected |
| G-21 | Changes to security rules are approved by someone other than the author, and the rationale and the changes are recorded | NIS2 Art. 21 | Not checked | [TASK-14](TASK-14-policy-release.md), PolicyChange | Have the author attempt to approve directly and confirm that it is rejected | Not connected |
| G-22 | Before rules are changed, it is tested under the same conditions that forbidden behavior is still blocked and normal work still continues | NIS2 Art. 21 | Not checked | [TASK-13](TASK-13-regression-harness.md), [Decision replay](#decision-replay-decision_replay) | Confirm the per-case before/after results with the same `fixture_set_digest` | `receiver-email-policy-improvement`, `receiver-summary-only` |
| G-23 | Changes that widen permissions are marked separately and acknowledged item by item by a human | NIS2 Art. 21 | Not checked | The per-kind comparison rules of the [Permission widening check](#permission-widening-check-permission_widening), [TASK-14 3.5](TASK-14-policy-release.md#35-permission-widening-check-permission_widening) | Insert changes that widen sets, numeric limits, data classes, CIDRs, and patterns one by one, and confirm that they are not approved without acknowledgment | Permission widening and per-kind comparison rule tests in chapter 7 of [TASK-14](TASK-14-policy-release.md). fixture not connected |
| G-24 | It is confirmed that applied rules are reflected in the actual execution path, and if confirmation fails, the hold is kept while the operator reverts to the previous rules | NIS2 Art. 21 | Not checked | [TASK-14](TASK-14-policy-release.md), [Policy release contract](#policy-deployment-contract) | Confirm the applied version after release. Inject an activation probe failure and confirm that the hold is kept in the `failed` state, and that the previous bundle is restored at a new epoch by a rollback request from `release_operator` | `policy-mixed-epoch`, `rollback-resume` |
| G-25 | Externally sourced components are pinned and managed as a list | NIS2 Art. 21 | Not checked | [environment lock](#environment-lock), [TASK-16](TASK-16-delivery-runbooks.md). There is no pre-installation review procedure | Confirm that the pinned version list matches the actual deployment | Not connected |
| G-26 | When an incident occurs, what happened can be reconstructed from the records alone | NIS2 Art. 23 | Not checked | [TASK-11](TASK-11-alignment-timeline.md) | Delete the execution Pod and then query the full timeline | `pod-lifecycle-late` |
| G-27 | There is a procedure to report incidents within a defined deadline | NIS2 Art. 23 | Not checked | None (follow-up needed). There is detection and holding but no reporting procedure | Measure the time from detection to a draft report. The comparison baselines are the deadlines known for NIS2 Art. 23: early warning in 24 hours, notification in 72 hours, and final report in 1 month, not yet checked against the original text | Not connected |
### Personal Data Items (P)

All of the bases are reference mappings to the GDPR. Personal data items are follow-up scope, so no fixtures are linked to them yet.

| ID | Check item | Basis (reference mapping) | Source text comparison | Corresponding Task | Verification method | Verification evidence |
| --- | --- | --- | --- | --- | --- | --- |
| P-01 | The system distinguishes which data is personal data, and the agent cannot lower that class | Art. 5, Art. 25 | Not compared | `data_class` in [enum definitions](#enum-definitions), [TASK-04](TASK-04-policy-gateway.md). There is no class dedicated to personal data | Confirm that the class of a session that received a personal data response goes up and does not go down | Not linked |
| P-02 | Sensitive data such as health and biometric information is classified separately and handled more strictly | Art. 9 | Not compared | None (follow-up needed) | Confirm that requests in the sensitive data class are decided by narrower rules | Not linked |
| P-03 | Only the items needed for the work are returned to the agent | Art. 5 | Not compared | Response handling in [TASK-05](TASK-05-service-adapters.md) and the [plan](../plan.md). There is no pseudonymization | Confirm that unnecessary personal data fields are removed from responses | Not linked |
| P-04 | Personal data is not used for purposes outside the purpose for which it was collected | Art. 5, Art. 6 | Not compared | [TASK-03](TASK-03-identity-approval.md). There are no purpose or legal basis fields | Confirm that queries and sends of personal data unrelated to the purpose are rejected or require approval | Not linked |
| P-05 | When personal data is sent externally, a person sees which items go out and approves it | Art. 5, Art. 32 | Not compared | [TASK-02](TASK-02-catalog-contracts.md), [TASK-03](TASK-03-identity-approval.md) | Confirm that a send containing unapproved fields is rejected | Not linked |
| P-06 | External services that receive personal data are limited to those under contract. This includes model providers | Art. 28 | Not compared | [TASK-02](TASK-02-catalog-contracts.md). There is no item that records whether a processor contract exists | Confirm that sending personal data to an unregistered target is rejected | Not linked |
| P-07 | Personal data is not sent outside the EU, or a basis for sending it is in place. This includes the processing location of model calls | Chapter V | Not compared | [TASK-05](TASK-05-service-adapters.md). Partial: model calls go out only to the registered project and location, so calls to locations outside the registration are blocked. However, if the location of the selected model is `global`, the processing location cannot be guaranteed, and there is no rule that restricts it to within the EU | Confirm that calls outside the allowed regions are rejected | Not linked |
| P-08 | Unnecessary personal data is kept out of prompts passed to the model | Art. 5, Art. 32 | Not compared | [TASK-02](TASK-02-catalog-contracts.md) content checker, [TASK-05](TASK-05-service-adapters.md) model profile. Partial: the content checker applies only to the `summary` of `receiver.submit` and not to `model.generate`. It is also not a general-purpose detector | Send content containing personal data in a model call and confirm that it is blocked or requires approval | Not linked |
| P-09 | Raw personal data is not put into records. Any raw data that is needed is separated into an access-restricted store, and records keep only a reference | Art. 5, Art. 25 | Not compared | [Normalization and hashing](#normalization-and-hashing), [TASK-04](TASK-04-policy-gateway.md) decision input, [TASK-07](TASK-07-audit-store.md), [TASK-05](TASK-05-service-adapters.md) `model_turns`. Partial: a simple hash of a sensitive value is not anonymization, so a hash is not used as a substitute for raw data. Raw model conversations are kept in a table dedicated to the model adapter and deleted after the session expires. The retention deadline for raw approval content was not confirmed in this table | Query the audit records and confirm that they contain neither raw personal data nor simple hashes of it | Not linked |
| P-10 | Raw personal data is kept only for the necessary period and can be erased when an erasure request arrives | Art. 5, Art. 17 | Not compared | [TASK-07](TASK-07-audit-store.md), [TASK-05](TASK-05-service-adapters.md). Partial: deletion of records past the retention period and deletion of raw model conversations after session expiry exist. There is no path for deletion on request. The relationship with the minimum retention (G-03) is described in G-03 | Confirm automatic deletion of raw data past the retention period and deletion on request | Not linked |
| P-11 | Stored personal data is encrypted, the people who can query it are restricted, and who queried it is recorded | Art. 32 | Not compared | [TASK-07](TASK-07-audit-store.md), [TASK-11](TASK-11-alignment-timeline.md). There is no query log | Confirm that queries by unauthorized users are rejected and that queries are logged | Not linked |
| P-12 | The agent does not on its own make decisions that have legal effects or similarly significant effects on individuals | Art. 22 | Not compared | [TASK-03](TASK-03-identity-approval.md), [TASK-04](TASK-04-policy-gateway.md). Actions that affect individuals are not classified separately | Confirm that such actions are not automatically allowed by a standing rule | Not linked |
| P-13 | When a data subject requests access to, rectification of, or erasure of their data, the request can be handled | Art. 12–22 | Not compared | None (follow-up needed) | Confirm that it is possible to find which records contain a specific person's data | Not linked |
| P-14 | If personal data is breached, what went out and where can be identified, so that the supervisory authority can be notified within 72 hours | Art. 33, Art. 34 | Not compared | [TASK-08](TASK-08-destination-evidence.md), [TASK-11](TASK-11-alignment-timeline.md). There is no notification procedure | In a breach scenario, identify the items that went out and their recipients from the records alone | Not linked |
| P-15 | An impact assessment is performed before deploying an adapter that handles personal data | Art. 35 | Not compared | None (out of scope). This is a documentation procedure, not a system feature | Confirm that an assessment document exists for each adapter | Not linked |

## Distinction Between Official Sources and Design

The following official sources were reviewed on 2026-10-11 for design reference. They serve as the basis for product features/APIs, while the business APIs, privilege separation, storage, and failure handling above constitute the implementation contract of this project. Items whose original texts were directly verified in this revision are indicated.

- [containerd/nri plugin.go](https://github.com/containerd/nri/blob/main/pkg/adaptation/plugin.go): fail-open behavior of `startContainer` and `isFatalError`, default `plugin_request_timeout` of 2 seconds (verified in source).
- [GKE containerd configuration](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/customize-containerd-configuration): three supported items (verified in documentation).
- [GKE node pool upgrade strategies](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/node-pool-upgrade-strategies): surge upgrade PDB respect limit of 1 hour (verified in documentation).
- [Agent Platform thought signatures](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/thought-signatures), [release notes](https://docs.cloud.google.com/gemini-enterprise-agent-platform/release-notes): Gemini 3 function calling signature return obligation and 400 error, incorporation of Vertex AI into Agent Platform (verified in documentation).
- [OPA bundles](https://www.openpolicyagent.org/docs/management-bundles), [opa/v1/rego](https://pkg.go.dev/github.com/open-policy-agent/opa/v1/rego), [opa/v1/bundle](https://pkg.go.dev/github.com/open-policy-agent/opa/v1/bundle), [bundle.go source](https://github.com/open-policy-agent/opa/blob/main/v1/bundle/bundle.go): `revision` of bundle `.manifest` (verified in documentation), `ParsedBundle` and `PrepareForEval` (verified in documentation), `NewCustomReader`, `WithBundleVerificationConfig`, `NewVerificationConfig(keys, id, scope, exclude)`, and the behavior of rejecting missing signature files only when `KeyID` is present (verified in main branch source).
- [encoding/json](https://pkg.go.dev/encoding/json), [net/http](https://pkg.go.dev/net/http), [net/http/httptrace](https://pkg.go.dev/net/http/httptrace): v1 allowing duplicate names, `ErrUseLastResponse`, default User-Agent, `WroteHeaders` definition (verified in documentation).
- [cyberphone/json-canonicalization](https://github.com/cyberphone/json-canonicalization): Go JCS candidate. The LICENSE body is an Apache License 2.0 notice (GitHub API classification is "Other"), there are no releases, and the only tag is `es6testfile` (verified in repository). Vendor by commit SHA (TASK-02).
- [PostgreSQL locks](https://www.postgresql.org/docs/17/explicit-locking.html), [INSERT](https://www.postgresql.org/docs/17/sql-insert.html): locks and unique conflicts, SELECT privilege requirement for `ON CONFLICT` (verified in documentation).
- [ADK models](https://adk.dev/agents/models/), [ADK base_llm.py](https://github.com/google/adk-python/blob/main/src/google/adk/models/base_llm.py), [llm_agent.py](https://github.com/google/adk-python/blob/main/src/google/adk/agents/llm_agent.py): `BaseLlm.generate_content_async` abstract method and `LlmAgent.model: Union[str, BaseLlm]` (main branch source, verified by TASK-15 owner). Re-verify against a pinned version.
- [FastAPI body](https://fastapi.tiangolo.com/tutorial/body/), [Pydantic configuration](https://docs.pydantic.dev/latest/api/config/): reference for input validation/extra rejection in Python services.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JSON canonicalization. Business semantic normalization is separate.
- [GKE WIF](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/workload-identity), [Secret Manager IAM](https://docs.cloud.google.com/secret-manager/docs/access-control): basis for KSA/resource permissions by role.
- [Cloud SQL GKE](https://docs.cloud.google.com/sql/docs/postgres/connect-kubernetes-engine), [GCS retention](https://docs.cloud.google.com/storage/docs/bucket-lock): reference for storage/permissions and retention. Permanent retention lock is a separate, irreversible operational decision.
- [GKE node isolation](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/isolate-workloads-dedicated-nodes), [Sandbox](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods), [NetworkPolicy](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/network-policy): empirically measured enforcement scope per mode.
- [GKE network policy logging](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/network-policy-logging): `log` and `delegate` in `spec.cluster.allow` and `deny` of the `NetworkLogging` object (`networking.gke.io/v1alpha1`, name `default`), annotations `policy.network.gke.io/enable-logging` and `enable-deny-logging`, Cloud Logging `policy-action` logs (resource type `k8s_node`) and node files on Standard clusters, record fields, 5-second aggregation of denied connections and `count`, fact that logs are dropped if exceeding 500 per second per node but policy enforcement is maintained, Dataplane V2 only (verified in documentation on 2026-10-12). Individual names of the drop counters and whether node-egress and hostNetwork traffic are recorded are not in the documentation, so they are kept as Q0.
- [Tetragon TracingPolicy](https://tetragon.io/docs/reference/tracing-policy/), [threat model](https://tetragon.io/docs/threat-model/): hooks, permissions, and kernel compromise limits. Empirically measured supported events.
- [OTel config](https://opentelemetry.io/docs/collector/configuration/), [resiliency](https://opentelemetry.io/docs/collector/resiliency/): reference for pipeline/queue; do not substitute durable audit contracts.
- [REA](https://rea.tools/): methodology reference for call path discovery.
