# Vendored: cyberphone/json-canonicalization (Go)

- Upstream: https://github.com/cyberphone/json-canonicalization
- Pinned repository commit: `32a48195b9b20fe67b1795e39e4509f14d860b45`
  (2026-10-11, "Merge pull request #38 from SashaMIT/fix/reject-invalid-unicode")
- Last commit touching the Go sources: `0c88af0958796de49dea4594a237fdee7c9014a3`
  ("Reject a surrogate pair that is not a pair, and invalid UTF-8.")
- Upstream path: `go/src/webpki.org/jsoncanonicalizer/` (GOPATH layout, no `go.mod`, no releases)
- License: Apache License 2.0, `LICENSE` copied unchanged from the repository root.

## Files

| file here | upstream file | git blob | SHA-256 of upstream file |
| --- | --- | --- | --- |
| `jsoncanonicalizer.go` | `go/src/webpki.org/jsoncanonicalizer/jsoncanonicalizer.go` | `ebc3f1c9fd5060b9eeb7a062fb3634d0724d5103` | `9c5e9f19aa888268a9369cc09a3c0ff1b115a17461e5cc038f29b059c69aca5b` |
| `es6numfmt.go` | `go/src/webpki.org/jsoncanonicalizer/es6numfmt.go` | `92574a3f4f303a8f8a38b7e775dd46b60334f96b` | `a5f31e4411d030c309b79d865329d02f90deeaabb9e926ceb0399cf053541e8c` |
| `upstream_test.go` | `go/src/webpki.org/jsoncanonicalizer/jsoncanonicalizer_test.go` | | `b8294110d215b2a2f921051e7c594cadbc3117b5860cba9e131a15fd83a2c17f` |
| `LICENSE` | `LICENSE` | `591211595aaa8d4b842a3aff2fcf26e32dc7f747` | `6821faaddedf2d78c95bb6d98b127e9e616097afd2f6bcc34389f000d13ab12d` |
| `testdata/{input,output,outhex}/*` | `testdata/{input,output,outhex}/*` | | copied unchanged |

`packages/canonical/testdata/crosscheck/canonicalize.js` is upstream `node-es6/canonicalize.js`
(blob `76b36f165c6d4d8bbef2791e48b7afaac24256b7`) from the same commit, used only by the
test-time cross-check script.

## Local modifications

Only the package clause: `package jsoncanonicalizer` -> `package jcs`, in the three Go files.
No other byte was changed. Verify with:

```
git -C <clone> checkout 32a48195b9b20fe67b1795e39e4509f14d860b45
diff <(sed 's/^package jsoncanonicalizer$/package jcs/' <clone>/go/src/webpki.org/jsoncanonicalizer/jsoncanonicalizer.go) jsoncanonicalizer.go
```

## Known properties (checked by tests in this directory)

- Top-level value must be an object or array.
- Duplicate keys, lone or reversed surrogates, invalid UTF-8 and NaN/Infinity are errors.
- `Transform` is not a validating JSON parser: number tokens go through `strconv.ParseFloat`,
  which also accepts non-JSON forms such as `0x1p4`. Callers in `packages/canonical` always run
  the strict JSON pre-check (or marshal from typed Go values) before calling `Transform`.
