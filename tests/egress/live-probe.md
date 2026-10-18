# Live transport probe (TASK-06)

`cmd/egress-probe` runs inside an admitted Pod with its actual namespace, labels
and KSA. It emits JSON observations and returns nonzero if any observation differs
from its expected result. It does not install resources, get tokens, change
policies, or send application requests. This is a test utility, not a service API.

Build using the existing image template, then push and resolve the resulting
digest in the environment's Artifact Registry:

```sh
docker build --platform linux/amd64 -f build/docker/go-service.Dockerfile \
  --build-arg CMD=./tests/egress/cmd/egress-probe -t "$PROBE_IMAGE_TAG" .
```

Use `/app` as the entrypoint. The execution probe profile requires an approved
digest and its exact entrypoint in `agent-exec-constraints`. Configuration uses
literal environment values; it needs no token volume, Secret, extra capability,
host namespace, or cluster permission. Keep the existing non-root/read-only
profile, exec placement, resource limits and probe bootstrap toleration.

`EGRESS_TARGETS` is a JSON array with 1–16 unique named targets. Each uses a literal
IP and port, avoiding an accidental DNS prerequisite for TCP tests:

```json
[
  {"name":"allowed-gateway","network":"tcp","address":"192.0.2.10:8443","expect":"reachable"},
  {"name":"direct-dns","network":"dns-udp","address":"192.0.2.53:53","query":"kubernetes.default.svc.cluster.local.","expect":"timeout"},
  {"name":"metadata","network":"tcp","address":"169.254.169.254:80","expect":"timeout"}
]
```

Replace documentation addresses with live values. Available networks are `tcp`,
`dns-udp` and `dns-tcp`; DNS requires an absolute query name and a successful
IPv4 answer. UDP socket creation alone is never success. Every probe has a
three-second deadline. Refusal, cancellation, NXDOMAIN and other errors remain
distinct from timeout and fail a `timeout` expectation.

For a positive control, the same image with `EGRESS_LISTEN=1` listens on TCP 8443
until SIGTERM. It immediately closes accepted connections and handles no HTTP or
application data. Run it as a clearly named test Pod under the target's admitted
KSA/label; do not attach it to a production Service. Connect to its Pod IP. Apply
the reviewed NetworkPolicy graph before testing, and preserve existing policies.

Collect the effective policies, image digest, source KSA/labels/Pod UID/node,
target endpoints, logs, exit status and positive controls. From an allowed
control-side KSA, verify DNS, metadata and Google API endpoints separately. Run
the execution probe against those endpoints, an allowed TCP listener, a forbidden
port, and a direct external IP. A missing positive control leaves the associated
denial test inconclusive. A timeout by itself does not prove NetworkPolicy was
the cause: routing, unavailable endpoints and other controls can also drop
traffic. Correlate dataplane drop evidence when claiming causal enforcement.

This does not test HTTP authorization, mTLS, Cloud SQL roles, credential broker,
GCS object permissions or ordinary `agent-runtime` startup readiness. The
bootstrap `probe-runner` has its own allowed destinations; inspect the runtime
policy separately and test the runtime profile when its readiness gate passes.

After the run, remove only test Pods and SAs created by the run, remove only its
image/entrypoint allowlist entries, and restore prior node-pool counts. Keep the
reviewed NetworkPolicies installed. Never clear readiness taints just to schedule
a test. Store real environment identifiers and raw evidence outside tracked
source files.

Local checks:

```sh
go test -race ./tests/egress/cmd/egress-probe
go vet ./tests/egress/cmd/egress-probe
```

These exercise actual local TCP and UDP DNS sockets, refusal vs isolation,
cancellation, and invalid target configuration. They are not GKE evidence.
