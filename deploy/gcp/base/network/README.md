# Network policy checkpoint

`allow-matrix.yaml` is the TASK-06 namespace/workload/infra allow graph.
`caller-map.yaml` records each COMMON internal API/caller row and its explicit
network path (including relays). The mapping is manually reviewed; tests detect
missing/new rows and edges, not application authorization correctness.

From the repository root:

```sh
go run ./tools/netpol-render
go run ./tools/netpol-render --check
go test ./tools/netpol-render ./tests/egress ./tests/platform/admission
python3 -m unittest discover -s tests/egress -p 'test_*.py'
```

The checked-in `rendered/policies.yaml` is a deterministic template, not an
applicable environment manifest. To render a concrete JSON Kubernetes List:

```sh
go run ./tools/netpol-render --values /path/to/network-values.json --out /tmp/policies.yaml
```

The values object requires exactly `control_plane_endpoint` (IPv4),
`cloudsql_private_ip` (IPv4), and `node_cidr` (bounded IPv4 CIDR), resolved from
the ignored environment lock. Never commit actual environment values. The
existing `deploy/gcp/base/render.py` also accepts these three keys alongside
its admission/image values and resolves the network templates in its output.
Apply only `network/rendered/policies.yaml`; the matrix and caller map are
renderer inputs, not Kubernetes API objects.

Static checks verify namespace+pod selector intersection, no execution-namespace
infra egress, fixed execution destinations/ports, TASK-06 example equivalence,
and COMMON caller coverage. These tests do not prove GKE enforcement, DNS,
metadata or external egress behavior. Live positive/negative connection probes
and evidence collection remain required before declaring M1-1/M2-1 complete.
The full graph contains later services; this does not assert those are deployed.

## Logging configuration check

TASK-06 section 7 `Apply logging configuration` compares the installed `NetworkLogging`
object and NetworkPolicy annotations with the reviewed files. Save the live
objects with the exact kubeconfig and context, then compare offline:

```sh
kubectl --kubeconfig "$KUBECONFIG" --context "$CONTEXT" \
  get networklogging default -o json > network-logging.json
kubectl --kubeconfig "$KUBECONFIG" --context "$CONTEXT" \
  get networkpolicies -A -o json > network-policies.json
go run ./tests/egress/cmd/logging-config-check \
  --network-logging network-logging.json --policies network-policies.json \
  > logging-config-report.json
```

It passes only when the live `NetworkLogging` identity and `spec` equal
`network-logging.yaml` exactly, exactly the eight `agent-exec`/`agent-adapters`
`<ksa>-allow` policies carry `policy.network.gke.io/enable-logging: "true"`,
and every rendered policy exists live. Other annotations and `status` are
ignored. Exit code 1 is a mismatch; exit code 2 is an input error, not a
result. A passing report shows configuration only: it does not show that any
connection was logged, that the node file is collected, or that the
`policy-action` exclusion applies. `go test ./tests/egress/...` also checks
that `network-logging.yaml` equals the TASK-06 3.4 block.
