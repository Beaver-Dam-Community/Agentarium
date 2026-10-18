# 20261014-task01-admission

| Item | Value |
| --- | --- |
| Task | TASK-01 |
| run_kind | `platform_admission_live` |
| Status | `pass` (all 34 executed passed, scope limited) |
| Original commit | `e18ecc0` (before rebase. The tree for test paths is identical to the commit below) |
| Implementation commit | `3a84d6a11f9144f81c80848693d4681b06a02e50` |
| Environment | `karrot-rina` / `agentarium-prod`, GKE `1.36.4-gke.1495002`, `asia-northeast3-a` |
| Execution time | roles 2026-10-14T12:22:51Z~12:23:01Z, exec 2026-10-14T12:38:53Z~12:39:10Z |
| Repetitions | 1 |

## What Was Tested

Parts of Chapter 7 of TASK-01, "Placement Bypass (Admission)", "exec profile separation", and "Resource Limits", were tested against a live API server. The test code is `tests/platform/admission/live_integration_test.go` and `live_exec_integration_test.go` (`-tags integration`).

- **Allowed Pods were actually created.** The `agent-targets` Pod became `Running` on the control node. The probe Pod tolerated the startup taint and became `Running` on the exec node. The runtime Pod and fixture Pod remained `Pending` due to the startup taint.
- **Forbidden variants were submitted with `dryRun=All`.** The API server executes both PSA and VAP, but does not persist objects.
- **Quota separation was also verified.** The runtime Pod was counted only in `agent-runtime-quota`, and the probe Pod was counted only in `agent-probe-quota`.

| Group | Passed/Total | Rejecting Entity |
| --- | --- | --- |
| Role Namespaces (`agent-targets`, `agent-adapters`) | 14/14 | PSA restricted, `agent-role-contract` |
| Execution Namespace (`agent-exec`) | 20/20 | PSA restricted, `agent-exec-contract`, `agent-exec-profile`, `agent-exec-probe-contract` |

Case-by-case expected values are in `expected.json`, and observed values are in `observed.jsonl`.

## Test Inputs

- **Images:** All images are digest references from the Artifact Registry `agentarium` repository (`inputs.images` in `manifest.json`).
  - The runtime, probe, and fixture images are **substitute images**. Only a process waiting for SIGTERM was placed at the specified entrypoint path.
  - Therefore, these results only verify admission and placement rules. Runtime functionality is not verified.
- **Allowlist:** Admission params were rendered with these digests only during the test. After the test ended, all lists were reverted to empty values (fail-closed).
- **Cleanup:** All test Pods and ServiceAccounts were deleted.

## Items Not Executed or With Limitations

- **Rejection of NRI bypass annotation:** `forbiddenAnnotationKeys` is determined in the Q0 runtime profile. It was not tested as it is currently empty.
- **Rejection of adding ephemeral containers:** Requires a running runtime Pod.
- **Complete rollout within 10 minutes:** Requires a runtime Deployment (TASK-15).
- **`resources` deletion variant:** Passed admission because LimitRange populated default values first. It was only recorded, and the relevant SPEC-QUESTION is in `deploy/gcp/base/namespaces/agent-exec-resources.yaml`.
- **Chapter 7 items not yet tested:** RBAC matrix, node-readiness gating, bootstrap sequence, and runtime observation.
- **Repetitions and raw data archiving:** Executed only once. Raw data was not separately archived in private GCS, and the JSON files in this directory are the curated copies.

## What Was Found and Fixed in This Run

- **runtime quota:** The API server rejected adding an ephemeral-storage item to a PriorityClass-scoped quota. Therefore, that item was removed ([#9](https://github.com/Beaver-Dam-Community/Agentarium/pull/9)).
- **CEL type checking:** An `undefined field` warning occurred on Quantity fields. Changed to read wrapped with `dyn()` (#9).
- **System Pods:** If startup taints are applied to both pools, GKE-managed components cannot be scheduled. Therefore, system-pool was added ([#7](https://github.com/Beaver-Dam-Community/Agentarium/pull/7)).

## Policies Added Afterwards

The `agent-role-status-metadata`, rejection of `pods/resize`, and target scoping of `node-readiness-scope` added after this run are not included in this run. Those policies were recorded in [20261015-task01-admission-delta](../20261015-task01-admission-delta/report.md).
