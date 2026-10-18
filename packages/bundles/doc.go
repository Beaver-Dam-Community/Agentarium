// Package bundles builds, digests and signs the OPA policy bundle that the
// gateway and adapters load (TASK-14 3.2, COMMON policy deployment contract, Appendix A).
//
// The flow is Build → CandidateDigest → Sign. Build assembles data.json from
// the catalog and the policy data, adds the Rego modules and the .manifest
// revision, and writes an unsigned tarball. CandidateDigest is the canonical
// digest of every file in that tarball except .signatures.json. Sign adds an
// ES256 .signatures.json in the OPA bundle signing format and returns the
// signed tarball and its artifact_digest (SHA-256 of the tarball).
//
// Tarballs are deterministic: OPA's bundle writer leaves every tar and gzip
// header time at zero and writes data.json with sorted keys, and Build sorts
// the modules by path, so the same inputs always give the same bytes.
//
// Activation (active_policy, epoch CAS, holds, lease ack) is not here; it is
// the rest of TASK-14.
package bundles
