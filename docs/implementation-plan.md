# Implementation Plan and Division of Work

This document sets the order in which two people split the implementation of the tech spec ([docs/tech-specs/](tech-specs/README.md)) and the paths each person owns. The implementation scope is the entire tech spec, and this document does not change that scope. The working rules that each person's AI agent follows are in [AGENTS.md](../AGENTS.md) at the repository root.

## 1. Milestones and Owners

The tables in this chapter have the same content as the GitHub milestones. Milestone names use the ID and name from the table as is. When a table changes, the milestones are updated with it.

**Preparation:** Agreement on the division of work and the rules is complete when the PR that adds this document is merged.

<a id="phase-0-foundation-2026-10-14-ref"></a>

### Phase 0: Foundation (2026-10-14)

| ID | Name | Owner | Scope | Completion criteria |
| --- | --- | --- | --- | --- |
| M0-1 | Shared Scaffold | Rina | TASK-02, chapter 3 shared files (`go.mod`, `packages/canonical/`, `migrations/` skeleton, Dockerfile, Makefile, and CI examples) | `packages/canonical` produces the expected digest for every vector in `testdata/vectors.json`. Cross-checking between the gateway and adapter binaries is done in M2-7 |
| M0-2 | Cluster Foundation | Rina | TASK-01 (GKE, two node pools, Namespace, admission), project-wide shared resources (Cloud SQL instance, Certificate Authority Service CA pool and issuance policy, Cloud KMS signing key, GCS bucket). IAM bindings for the shared resources belong to TASK-06 | Allowed and forbidden Pod tests pass, shared resources created |
| M0-3 | Q0 Baseline Validation | Rina | From TASK-01 Q0, observation of three kinds of kernel behavior and the node file format of network policy logs | Observable range recorded |

<a id="phase-1-core-service-interfaces-2026-10-15-morning-chapter-5-table-ref"></a>

### Phase 1: Core Service Interfaces (2026-10-15 morning, chapter 5 table)

| ID | Name | Owner | Scope | Completion criteria | Prerequisites |
| --- | --- | --- | --- | --- | --- |
| M1-1 | Core Service Deployment | Rina | From TASK-06, the KSA, IAM, and NetworkPolicy for identity, audit, and control-health | The three services start in the cluster and connect to the DB | M0-2 |
| M1-2 | Certificate Issuance | Siu | TASK-03 3.3 (CAS issuance, `registered_workloads`, `issued_certificates`, trust bundle), the TASK-03 schema that TASK-10 reads (including `work_readiness_session_view`), initial registration based on the KSA table including `netpol-collector` | Other services receive mTLS certificates | M0-1, M1-1 |
| M1-3 | Audit Ingestion API | Rina | TASK-07 audit schema, `audit_append()`, `POST /internal/audit/events` | Audit events from other services are stored | M0-1, M1-1 |
| M1-4 | Health API Skeleton | Rina | TASK-10 lease reception, control-health query response | The gateway receives responses in the defined format | M1-1 |

<a id="phase-2-component-implementation-2026-10-15-ref"></a>

### Phase 2: Component Implementation (2026-10-15)

| ID | Name | Owner | Scope | Completion criteria | Prerequisites |
| --- | --- | --- | --- | --- | --- |
| M2-1 | Egress Controls & Credentials | Rina | Rest of TASK-06 (full allow table, RBAC, credential broker, network policy logging configuration) | Direct DNS, internet, and metadata access denied. Discovery bucket permission tests pass: the `discovery-snapshot` KSA succeeds at object create, get, and list while rewriting the same name and delete are denied, the `discovery` KSA can only read, and other KSAs are denied access (PR #8) | M0-2 |
| M2-2 | Audit Export | Rina | Rest of TASK-07 (outbox exporter, manifest signing, verifier) | Records can be queried even after Pod deletion | M1-3 |
| M2-3 | Node Sensors | Rina | TASK-09 (Tetragon policy, exporter, lifecycle recorder) | Ground-truth events observed | M0-3, M1-3 |
| M2-4 | Correlation & Health | Rina | TASK-10 (correlation join, hold decision and release, risk event hold) | Hold on sensor failure, recovery after probe | M2-3, M1-2 |
| M2-5 | Sessions, Approvals & Reservations | Siu | Rest of TASK-03 (session/claim/approval API, coordinator transaction, approval screen) | Tampering and concurrent reuse rejected | M1-2, M1-3 |
| M2-6a | Initial Policy Bundle | Siu | From TASK-14, the minimum part needed for gateway loading (bundle build and KMS ES256 signing in `packages/bundles/`, `desired_bundle` migration and writing the first row) | The gateway loads the first signed bundle. Conversion of the KMS signature to JWS is a Q0 item | M0-1, M0-2 |
| M2-6 | Gateway Policy Decisions | Siu | TASK-04 (Rego, embedded OPA, decision storage, execution forwarding) | Allow, pending approval, and deny reproduced | M2-5, M1-4, M2-6a |
| M2-7 | Service Adapters | Siu | TASK-05 (transport, query, send, and model adapters) | Targets and bodies changed after approval are blocked before sending. `tests/contracts` confirms that gateway and adapter digests match | M2-6, M2-1 |
| M2-8 | Destination Evidence | Siu | TASK-08 (receiver, evidence-collector) | Acceptance and actual receipt distinguished, late receipts and duplicates reproduced | M1-2, M1-3 |
| M2-9 | Network Policy Records | Rina | TASK-09 node collector, TASK-10 3.7 (NetworkFinding, collection gaps) | Blocked and established distinguished, gaps recorded | M0-3, M2-4 |

<a id="phase-3-end-to-end-integration-2026-10-16-early-morning-together-ref"></a>

### Phase 3: End-to-End Integration (2026-10-16 early morning, together)

| ID | Name | Completion criteria |
| --- | --- | --- |
| M3-1 | Happy Path | Session → approval → gateway → adapter → receiver → receipt connect end to end, and the audit records can be queried |
| M3-2 | Denial Paths | Forbidden requests and contract tampering are rejected before sending, and direct egress from the execution Pod is blocked |
| M3-3 | Observation Pipeline | Kernel events are linked to requests, and hold and recovery on sensor failure work |

<a id="phase-4-integration--delivery-2026-10-16-ref"></a>

### Phase 4: Integration & Delivery (2026-10-16)

Owners are written into the table before this phase starts.

| ID | Name | Scope | Completion criteria |
| --- | --- | --- | --- |
| M4-1 | Alignment Timeline | TASK-11 | Display of match, mismatch, unconfirmed, and observation gaps |
| M4-2 | Policy Proposals | TASK-12 | Structured proposals generated, the model does not gain permission to change operations |
| M4-3 | Regression Tests | TASK-13 | Before/after comparison with the same `fixture_set_digest` |
| M4-4 | Policy Deployment & Rollback | Rest of TASK-14 | Unapproved and tampered deployments rejected, activation confirmed, rollback |
| M4-5 | Runtime Integration | TASK-15 | Work starts only after worker observation and session linking, full demo |
| M4-6 | Delivery Artifacts | TASK-16 | Installation guide and measurement report |

<a id="phase-5-assist--measurement-ref"></a>

### Phase 5: Assist & Measurement

| ID | Name | Scope |
| --- | --- | --- |
| M5 | Assist & Measurement | AI assist features (approval intent comparison, call path discovery), `startup_guard_gate`, `measurement` fixture, optional features. Placed at the end of each Task |

- **Implementation order:** Within each Task, follow the grouping order set by the tech spec. Implement the MVP-required contracts first, then proceed in the order of AI assist features, the independent gate `startup_guard_gate`, the `measurement` scope, and optional features ([plan.md](plan.md) completion criteria table).
- **Q0:** Among the TASK-01 Q0 items, those needed for `startup_guard_gate` do not block other Tasks even if their results are late. The cluster and the Q0 harness are set up first, and the remaining Q0 items continue on 2026-10-15.
- **PR #3 content:** Rina implements network policy records (TASK-06 3.4, TASK-10 3.7) and risk event hold (TASK-10 3.2) based on the merged content of PR #3. Appendix C and TASK-13 `governance_refs` are handled in the integration phase.
- **2026-10-14 Siu:** Reviews the TASK-02 code. TASK-03, 04, and 05 are built on top of it.

## 2. Owned Paths

The paths are taken from the "Implementation files" table in chapter 6 of each Task document. A person who is not the owner does not edit these paths directly (chapter 4).

| Owner | Task | Paths |
| --- | --- | --- |
| Rina | TASK-01 | `platform/gcp/` (excluding the TASK-06 paths below; includes project-wide shared resources such as the Cloud SQL instance, CA pool, KMS key, and GCS bucket), `services/node-readiness/`, `tests/platform/` |
| Rina | TASK-02 | `catalog/gcp/`, `packages/canonical/`, `services/discovery/`, `tools/discovery-snapshot/`, `tests/contracts/` |
| Rina | TASK-06 | `deploy/gcp/base/` (including rbac and network), `platform/gcp/iam/`, `platform/gcp/logging/`, `services/credential-broker/`, `tools/netpol-render/`, `tests/egress/` |
| Rina | TASK-07 | `services/audit/`, `deploy/gcp/observe/`, `tests/audit/` |
| Rina | TASK-09 | `sensors/`, `services/lifecycle-recorder/`, `deploy/gcp/sensors/`, `tests/kernel/` |
| Rina | TASK-10 | `services/control-health/`, `services/correlation/`, `services/start-coordinator/`, `tests/correlation/` |
| Siu | TASK-03 | `services/identity/`, `services/coordinator/`, `packages/contractview/`, the approval screen in `apps/console/` |
| Siu | TASK-04 | `services/gateway/`, `services/intent_check/`, `packages/decisions/`, `packages/policyloader/`, `policies/gateway/`, `tests/gateway/` |
| Siu | TASK-05 | `services/adapters/`, `packages/adapters/`, `packages/transport/` |
| Siu | TASK-08 | `services/receiver/`, `services/evidence-collector/`, `tests/evidence/` |
| Siu | Part of TASK-14 (M2-6a) | Bundle build and signing in `packages/bundles/`, `desired_bundle` migration. The owner of the releaser and the rest is decided in the integration phase |

- **Task documents:** `docs/tech-specs/TASK-xx` is edited by the owner of that Task. COMMON.md, plan.md, architecture.md, and the tech-specs README are jointly owned and follow the separate PR rule in chapter 4.
- **Content of shared resources:** TASK-03 3.3 defines the issuance policy of the CA pool, and TASK-07, 13, and 14 define the KMS key and bucket settings. Rina creates them in `platform/gcp/`, and the owner of the relevant Task reviews them.
- **Deployment configuration for Siu's services:** The KSA, IAM, RBAC, and NetworkPolicy for the TASK-03, 04, 05, and 08 services live in the TASK-06 paths. TASK-06 generates these values from the KSA table and the internal API table in COMMON. Siu does not edit the manifests directly; he checks that the tables are correct and, if needed, opens a separate PR that fixes the tables.

## 3. Shared files

These are files that several Tasks use together. Rina creates them together with TASK-02 on 2026-10-14.

| File | Rule |
| --- | --- |
| `go.mod`, `go.sum` | The repository-wide Go module. Whoever adds a dependency commits it. On a conflict, do not fix it by hand; rebase and regenerate both files with `go mod tidy` |
| `migrations/` | Following the tech spec, keep migrations in one shared directory in `golang-migrate` format (`{version}_{title}.up.sql`/`.down.sql`), and prefix each file name with the Task prefix (`identity_`, `audit_`, etc.). Write `version` as a UTC timestamp (`YYYYMMDDHHMMSS`). golang-migrate does not apply files whose version is lower than the current version, so before opening a PR, rebase onto main and renumber the new file so its version is greater than the last version on main. Do not edit a migration file that is already merged; replace it with a new file |
| `packages/canonical/` | Every service uses it to compute digests. It is completed on 2026-10-14, and any later change goes through a separate PR as described in chapter 4 |
| Dockerfile, Makefile, CI workflow | Rina creates them for one service as an example. The other services copy the same format |
| `deploy/gcp/environment.lock.json` | TASK-16 owns the schema. Until the integration phase, each person adds only the keys of their own Task |

## 4. When you need to change someone else's files

1. Do not change another owner's paths or co-owned documents inside a feature PR.
2. If a change is needed, open a separate PR that contains only that change. Name the branch `<yourname>/change-<topic>`, and write in the PR description why the change is needed and which Tasks it affects.
3. The owner of that path reviews and merges it. A PR that changes COMMON.md is reviewed by both people.
4. Do not merge code that depends on the change before the separate PR is merged. While waiting, proceed with a temporary adapter or stub inside your own paths.

<a id="5-dependencies-between-components-and-how-to-handle-them-ref"></a>

## 5. Dependencies between components and how to handle them

Once TASK-01 and TASK-02 are done, the only remaining development prerequisite between the two people's Tasks is TASK-06 ↔ TASK-05. However, there are more integration dependencies needed at runtime.

| Dependency | Description | Handling |
| --- | --- | --- |
| TASK-05 ↔ TASK-06 | The receiver send adapter calls the credential broker, and the adapter destination is entered in the egress allow table | Each person implements against the COMMON internal API table and the `credential_bindings` definition. If the definition must change, do it through a separate PR as described in chapter 4 |
| TASK-03 → Rina's services | The identity service issues mTLS certificates for every service. TASK-10 reads TASK-03's `registered_workloads`, `issued_certificates`, and `work_readiness_session_view` | Siu deploys the certificate issuance path and schema first, on the morning of 2026-10-15 |
| TASK-07·10 → TASK-04 | The gateway calls the audit storage API and the Health API, and runs `audit_append()` directly in the DB | Rina deploys the audit schema, `audit_append()`, and the Health API skeleton first, on the morning of 2026-10-15 (M1-3, M1-4) |
| TASK-06 → core services | KSA, IAM, and NetworkPolicy must exist before identity, audit, and control-health can start | Rina does the part of TASK-06 for these three services first thing on the morning of 2026-10-15 (M1-1) |
| TASK-14 → TASK-04 | The gateway returns 503 `POLICY_UNAVAILABLE` when there is no signed bundle and no `desired_bundle` row | Siu builds the minimal bundle path of TASK-14 before the gateway (M2-6a) |
| TASK-06 KSA table → TASK-03 initial registration | The initial values of `registered_workloads` and `component_principals` are built from the TASK-06 KSA table. This table contains `netpol-collector` | When inserting the initial values in M1-2, register `netpol-collector` as well |

## 6. Merging and status reporting

- As soon as one section of a Task passes its unit tests, merge it into main as a small PR. Do not merge everything at once in the early hours of 2026-10-16.
- Change `implementation_status` and `functional_verification` in each Task document's frontmatter only when there is evidence. Do not mark a result that passed with a mock or stub as functionally complete.
- Do not delete items that are not finished on schedule; leave them in their current state. The submission materials also follow that state.
