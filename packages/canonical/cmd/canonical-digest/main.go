// Command canonical-digest computes the Agentarium canonical digest
// (SHA-256 of the RFC 8785 JCS serialization) of one JSON document, using the
// same packages/canonical code as the Go services. Python tools use it for
// report_digest, fixture_set_digest and governance_map_digest instead of
// re-implementing JCS (COMMON "normalization and hashing").
//
// Usage:
//
//	canonical-digest [-mode digest|jcs] < document.json
//
// Input (stdin): exactly one JSON object or array in UTF-8. It is rejected
// (exit 1, message on stderr, nothing on stdout) on invalid JSON or UTF-8,
// lone surrogate escapes, duplicate keys, integers outside ±(2^53-1),
// non-finite numbers, a top-level scalar, or trailing data. Fractions and
// exponents are accepted and serialized as ECMAScript numbers, except that a
// value which is integral (9007199254740993.0, 1e16) must also lie within
// ±(2^53-1); otherwise distinct inputs would share a digest.
// The caller builds the exact object to hash, including any ordering such as
// fixture_id-sorted lists; the tool does not reorder arrays.
//
// Output (stdout):
//
//	-mode digest (default)  64 lowercase hex characters and "\n"
//	-mode jcs               the JCS bytes, without a trailing newline
//
// Exit status: 0 success, 1 rejected input or read error, 2 usage error.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("canonical-digest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", "digest", "output: digest (SHA-256 hex) or jcs (canonical bytes)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || (*mode != "digest" && *mode != "jcs") {
		fmt.Fprintln(stderr, "usage: canonical-digest [-mode digest|jcs] < document.json")
		return 2
	}
	in, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintln(stderr, "read stdin:", err)
		return 1
	}
	c, err := canonical.JCS(in)
	if err != nil {
		fmt.Fprintln(stderr, "invalid input:", err)
		return 1
	}
	if *mode == "jcs" {
		_, err = stdout.Write(c)
	} else {
		_, err = fmt.Fprintln(stdout, canonical.SHA256Hex(c))
	}
	if err != nil {
		fmt.Fprintln(stderr, "write stdout:", err)
		return 1
	}
	return 0
}
