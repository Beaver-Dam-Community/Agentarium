# M3-1 action path manifests

`generate.py` writes `services.yaml` (policy-gateway, coordinator,
receiver-sender, receiver, evidence-collector) and `agent-runtime.yaml` (the
agent-exec demo runtime Pod). Edit the generator, then run
`python3 deploy/gcp/base/action-path/generate.py`; `--check` (also a unit test)
fails on drift. `deploy/gcp/base/render.py` renders both files with the other
base manifests and rejects any public exposure.

Flags and env follow the binaries of the M3-1 code PRs (#218, #220, #222,
#223, #225, #227, #230, #234, #236, #237) as they are merged on the
integration branch, not any single branch:

- Every Pod bootstraps its certificate in memory from workload-identity with
  a projected `agentarium-identity` token (`--identity-url`,
  `--bootstrap-token`, #218). The runtime goes through the gateway relay.
- Each audit producer has one Recreate replica and an epoch PVC
  (`<ksa>-epoch`). Never delete or recreate the PVC for the same source id.
- Services are ClusterIP only. The gateway and receiver use the fixed
  ClusterIPs `network.gateway_cluster_ip` and `receiver.cluster_ip` from the
  lock. `receiver-probe` (TASK-02 `targets.yaml`, the activation probe target)
  is a second Service over the receiver Pods (receiver KSA and URI SAN) at
  `receiver.probe_cluster_ip`.
- Every Deployment has one replica and the
  `iam.gke.io/gke-metadata-server-enabled` nodeSelector (cloud-sql-proxy uses
  Workload Identity); `generate.py` refuses manifests that break either.
- The evidence-collector lease source id is fixed
  (`evidence-collector/receiver-primary`) because control-health matches
  target lease sources against its profile `sources` binding.
- The runtime Pod has no args, no `valueFrom` and only the `work` and
  `identity` volumes (agent-exec admission), so the trust bundle is the PEM
  text in `AGENTARIUM_TRUST_BUNDLE_PEM`.

Install inputs outside these files (runbook step 7): ConfigMaps
`agentarium-bundle-keys` (`<bundle_key_id>.pem`) in agent-control and
agent-adapters, `agentarium-model-profiles` (`model-profiles.json`) and
`agentarium-identity-role-map` (`role-map.yaml`) in agent-control,
`agentarium-trust` in every role Namespace, the control-health profile keys
`environment`, `readers` and `sources`, and the install data in
`../installer/`.
