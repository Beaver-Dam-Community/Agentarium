// Command identity-trust-bundle prints the CA certificates of the CAS pool as
// one PEM bundle, de-duplicated and sorted. TASK-06 (TASK-06 owner) puts the
// output into ConfigMap agentarium-trust in every role namespace; during a CA
// rotation the pool returns the old and new CA together (TASK-03 3.3.1).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	privateca "cloud.google.com/go/security/privateca/apiv1"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/issuer"
)

func main() {
	pool := flag.String("ca-pool", os.Getenv("IDENTITY_CA_POOL"), "CAS pool: projects/<p>/locations/<l>/caPools/<pool>")
	flag.Parse()
	if *pool == "" {
		fmt.Fprintln(os.Stderr, "identity-trust-bundle: --ca-pool is required")
		os.Exit(2)
	}
	ctx := context.Background()
	c, err := privateca.NewCertificateAuthorityClient(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity-trust-bundle:", err)
		os.Exit(1)
	}
	defer c.Close()
	bundle, err := issuer.CAS{Client: issuer.GoogleCAS{C: c}, Pool: *pool}.TrustBundle(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity-trust-bundle:", err)
		os.Exit(1)
	}
	fmt.Print(bundle)
}
