// Package canonical is the single Go implementation of Agentarium request
// normalization, RFC 8785 JCS and SHA-256 digests (TASK-02, COMMON
// "normalization and hashing"). The gateway and the adapters import the same version.
//
// Request path:
//
//	ca, err := canonical.DecodeClientAction(raw)            // 413/422, outer ClientAction
//	env, content, err := canonical.Normalize(ca, raw, trusted, catalog)
//
// DecodeClientAction runs the strict pre-check of TASK-02 3.1 on raw bytes
// (UTF-8, surrogate escapes, duplicate and case-only duplicate keys, depth 16,
// key length 128, integer-only numbers within ±(2^53-1), no trailing tokens,
// exact struct-tag keys) before decoding with DisallowUnknownFields and
// UseNumber. Normalize repeats that procedure for the operation typed
// requested_target and arguments, resolves the catalog target, runs the
// receiver content checker and computes action_digest from the fixed 10-key
// hash object. It performs no I/O.
//
// Catalogs are read with LoadCatalogDir/ParseCatalogYAML (strict YAML, Appendix A)
// or ParseBundleCatalog (bundle data.catalog JSON) and carry catalog_digest.
//
// JCS is the vendored github.com/cyberphone/json-canonicalization Go
// implementation in internal/jcs (see internal/jcs/VENDOR.md). Shared test
// vectors are in testdata/vectors.json; testdata/crosscheck recomputes them
// with the upstream JavaScript reference.
package canonical
