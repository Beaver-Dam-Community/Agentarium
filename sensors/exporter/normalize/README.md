# Tetragon 1.7.1 kernel normalizer

`Normalizer.Prepare` is the `acquire.Config.Normalize` callback for the pinned
Tetragon JSON file export. It recognizes `process_exec`, `process_exit`, and
kprobes `tcp_connect`, `tcp_set_state`, `security_file_open`,
`__x64_sys_openat`. Other events/hooks and aggregation fail closed. This is a
narrow adapter, not a running exporter or a complete Tetragon event dispatcher.
It implements the merged observation wire corrections in
[shared spec PR #87](https://github.com/Beaver-Dam-Community/Agentarium/pull/87)
and the collector/WAL in [#58](https://github.com/Beaver-Dam-Community/Agentarium/pull/58).
Both prerequisites are merged; this library does not enable a production exporter.

The raw JSON checker retains duplicate-key, Unicode and grammar checks without
applying COMMON's safe integer range to upstream numeric tokens. The real input
is decoded without float64: socket cookies accept exact decimal strings or
integer tokens through the full uint64 range. Only the validation copy replaces
numbers. The resulting wire record uses COMMON's strict JSON and canonical JCS.

- `sock_ptr` is exactly 16 lowercase hex characters, without `0x`.
- `tcp_state` keeps only top-level `tcp_new_state` (1 or 7) as the state authority.
  Its process/parent/start/PID/container/Pod/docker/netns/lifecycle fields are null.
  Softirq process information is not passed to the scope resolver, even when the
  raw event identifies a kube-system Pod. The resolver receives node/boot,
  source time, socket pointer and tuple to make an authoritative scope decision.
- `tcp_connect` records a connection attempt. It does not infer establishment,
  application request success, session ID, or adapter action attribution.
- Process-context metadata uses observed exec/parent/start/host PID/netns and a
  trusted lifecycle resolver for full container/Pod/lifecycle IDs. Raw Pod labels,
  Pod UID and container ID never become authoritative metadata. The observed
  docker prefix is reduced to the spec's first 15 hex characters; Q0's upstream
  field is longer. This prefix is only a lookup aid, never identity proof.
- Node, Pod and lifecycle IDs use canonical lowercase UUID syntax. Observed host
  PID must fit PostgreSQL's positive signed integer; an unobserved PID stays null.
- File records retain paths only from an exact configured protected-path
  allowlist. `file_arg.flags` is a path-resolution string, not `f_flags`, and is
  never stored as access flags. `security_file_open` retains observed return code
  but does not imply the user's entire file operation succeeded. `openat` retains
  its actual access flags and negative return value as `return_errno`; successful
  fd values (including zero) are not retained and the optional errno key is absent.
- Exec binary is plaintext only on the configured exact allowlist; otherwise it
  is a lowercase SHA-256 digest of UTF-8 path bytes. CWD is digested. Task argv and
  environment have no decoded fields and are never stored or hashed; optional
  `args_digest` is omitted. Other attributes are discarded.

The trusted resolver returns Include, Exclude, or Unknown as an **internal adapter
decision**, not a new wire enum. Unknown, nil resolver, resolver failure or absent
metadata status returns `ErrMetadataUnavailable`; neither sequence nor input
checkpoint advances. Exclude must be backed by positive lifecycle/scope evidence.
A non-protected file path is excluded directly by the explicit local allowlist.
Only included events produce a Build callback. The callback uses
`canonical.KernelEventID`, assigns spooled time, and computes `record_digest`
using `canonical.DigestWithoutKeys(..., "record_digest", "received_at")`.
`received_at` is never included in the request. WAL owns reservation and fsync.

Installation must supply the authenticated sensor/node/boot identity, expected
Tetragon node name, rule hash, normalization version, coverage value, binary/path
allowlists and authoritative lifecycle/scope resolver. No default metadata-status
or coverage vocabulary is invented. `upstream_event_ref` is null because this
adapter has no stable upstream event reference. The metadata adapter must express
its evidence limits in its approved metadata status; this code adds no new reason
or provenance wire fields. Trusted runtime resolution and registration are not
implemented here. Configuration and resolver must remain stable for the lifetime
of the normalizer; injected clock/resolver must support concurrent calls.

## Evidence

Tests read the existing, real Q0 JSON export files under:

- `evidence/gcp/runs/20261014-task01-q0-min/raw/run1-events.relevant.jsonl`
- `evidence/gcp/runs/20261015-task01-q0-min-2/raw/run3-events.relevant.jsonl`

No original production IDs or raw task arguments are copied into new fixtures.
Privacy, numeric-boundary and wrong-softirq-Pod cases mutate those inputs with
synthetic values in memory. Upstream scalar/oneof semantics are checked against
[Tetragon v1.7.1 tetragon.proto](https://github.com/cilium/tetragon/blob/v1.7.1/api/v1/tetragon/tetragon.proto)
and [events.proto](https://github.com/cilium/tetragon/blob/v1.7.1/api/v1/tetragon/events.proto).
An omitted ProcessExit status is the proto3 uint32 default zero, not a guessed
runtime outcome.

`go test -race ./sensors/exporter/...` covers original Q0 shape, full uint64 socket
pointers, both TCP states, wrong softirq process metadata, argv/environment
non-retention, protected-path exclusions, fd/errno separation, unknown metadata,
UUID/PID bounds, canonical identity/digests, concurrent Build calls and real
Collector/WAL sequence/checkpoint behavior. `go test ./...` and `go vet ./...`
check repository integration. These tests do not prove live collection, complete
hook coverage, lifecycle resolution, collector DB acceptance, or GKE enforcement.
