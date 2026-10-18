// Command console is the operator's local approval console (M3-1 demo). It
// runs on the operator's laptop, never in the cluster. It serves one embedded
// page on a loopback address and proxies a small JSON API to the identity
// console routes (sessions and approvals), reached through kubectl
// port-forward.
//
// The Google ID token comes from -token-command and stays in this process:
// it is cached in memory until shortly before exp, sent only to identity and
// never logged, written to disk or returned to the browser. The identity
// server is verified against -ca-file and its exact URI SAN. The local API
// requires the per-process key printed at startup and rejects requests whose
// Host or Origin is not this listener.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "console:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fl := flag.NewFlagSet("console", flag.ContinueOnError)
	listen := fl.String("listen", "127.0.0.1:0", "loopback address for the local page (port 0 picks a free port)")
	identityURL := fl.String("identity-url", "https://workload-identity.agent-control.svc:18443", "identity base URL; its host is verified by URI SAN, not DNS")
	dialAddr := fl.String("identity-dial", "127.0.0.1:18443", "host:port to dial for the -identity-url host (the kubectl port-forward); required, because the -identity-url port is the port-forward port, not the Service port 8443")
	caFile := fl.String("ca-file", "", "PEM trust bundle that verifies the identity server (required)")
	san := fl.String("identity-san", workloadcert.IdentitySAN, "exact URI SAN the identity server certificate must carry")
	tokenCmd := fl.String("token-command", "gcloud auth print-identity-token", "command that prints a Google ID token on stdout; run without a shell and split on whitespace with strings.Fields, so quotes and escapes are not interpreted")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if fl.NArg() != 0 {
		return fmt.Errorf("unexpected arguments %v", fl.Args())
	}
	if *caFile == "" {
		return errors.New("-ca-file is required")
	}
	if h, p, err := net.SplitHostPort(*dialAddr); err != nil || h == "" || p == "" {
		return fmt.Errorf("-identity-dial %q: must be host:port of the identity port-forward (empty is not allowed: -identity-url uses the port-forward port, not the Service port 8443)", *dialAddr)
	}
	if err := checkLoopbackListen(*listen); err != nil {
		return err
	}
	roots, err := loadRoots(*caFile)
	if err != nil {
		return err
	}
	tokens, err := newTokenSource(*tokenCmd)
	if err != nil {
		return err
	}
	ic, err := newIdentityClient(*identityURL, roots, *san, *dialAddr, tokens)
	if err != nil {
		return err
	}
	key, err := randomKey()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	logger := log.New(os.Stderr, "console: ", log.LstdFlags)
	s := &server{key: key, port: port, identity: ic, logger: logger}
	// The key is printed once, in the fragment, which the browser does not
	// send to the server; the page sends it back in a header. Whoever reads
	// this output can approve as the operator through the loopback API (a
	// local process can forge Origin), so the console must be started from
	// the operator's own terminal, never by an agent or inside an agent
	// session.
	fmt.Fprintln(os.Stderr, "console: start this only from your own terminal, never through an agent harness or a ! command in an agent session; anyone who sees the URL below can approve as you.")
	fmt.Printf("Approval console: http://%s/#k=%s\n", net.JoinHostPort(host, port), key)
	srv := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second, // > tokenTimeout + identity client timeout
		IdleTimeout:       60 * time.Second,
		ErrorLog:          logger,
	}
	return srv.Serve(ln)
}

func randomKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
