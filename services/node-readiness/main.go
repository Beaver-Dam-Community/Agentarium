// Command node-readiness removes the start taint
// agentarium.io/observe-not-ready=true:NoSchedule only from nodes whose
// TASK-10 control-health conditions all hold, and re-adds it otherwise
// (TASK-01 3.5).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
	"github.com/Beaver-Dam-Community/Agentarium/services/node-readiness/internal/controlhealth"
	"github.com/Beaver-Dam-Community/Agentarium/services/node-readiness/internal/controller"
)

// selfSAN is the node-readiness service identity requested in --identity-url
// mode (TASK-06 KSA table, agent-control/node-readiness).
const selfSAN = "spiffe://agentarium.internal/ns/agent-control/sa/node-readiness"

// version is set with -ldflags "-X main.version=..." and reported as active_version.
var version = ""

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("node-readiness exited", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	var (
		kubeconfig     = flag.String("kubeconfig", "", "kubeconfig path; empty uses in-cluster config")
		healthURL      = flag.String("control-health-url", "", "control-health base URL, https://host:8443 (required)")
		healthSAN      = flag.String("control-health-san", controlhealth.DefaultServerSAN, "expected control-health server URI SAN")
		identityURL    = flag.String("identity-url", "", "identity HTTPS origin for in-memory certificate bootstrap (TASK-03 3.3.2); replaces --tls-cert-file/--tls-key-file")
		tokenFile      = flag.String("bootstrap-token", "", "projected agentarium-identity token file (required with --identity-url)")
		certFile       = flag.String("tls-cert-file", "", "client certificate PEM (required without --identity-url)")
		keyFile        = flag.String("tls-key-file", "", "client private key PEM (required without --identity-url)")
		caFile         = flag.String("tls-ca-file", "", "trust bundle PEM (required)")
		resync         = flag.Duration("resync", 5*time.Second, "per-node re-evaluation interval")
		leaseInterval  = flag.Duration("lease-interval", 5*time.Second, "lease heartbeat interval")
		leaseTTL       = flag.Duration("lease-ttl", 15*time.Second, "lease TTL")
		requestTimeout = flag.Duration("request-timeout", 10*time.Second, "control-health request timeout")
		workers        = flag.Int("workers", 2, "reconcile workers")
	)
	flag.Parse()
	if *healthURL == "" {
		return errors.New("--control-health-url is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var httpClient *http.Client
	if *identityURL != "" {
		if *tokenFile == "" || *caFile == "" {
			return errors.New("--bootstrap-token and --tls-ca-file are required with --identity-url")
		}
		if *certFile != "" || *keyFile != "" {
			return errors.New("--tls-cert-file/--tls-key-file cannot be combined with --identity-url")
		}
		// The certificate is bootstrapped and renewed in memory; a failed
		// first bootstrap stops the start (fail closed).
		m := &workloadcert.Manager{URL: *identityURL, TokenFile: *tokenFile, CAFile: *caFile, SAN: selfSAN}
		if err := m.Start(ctx, func() { logger.Error("service certificate renewal failed") }); err != nil {
			return fmt.Errorf("identity certificate bootstrap: %w", err)
		}
		httpClient = m.Client(*healthSAN, true)
		httpClient.Timeout = *requestTimeout
	} else {
		tlsCfg, err := controlhealth.LoadTLSConfig(controlhealth.TLSFiles{
			CertFile: *certFile, KeyFile: *keyFile, CAFile: *caFile,
		}, *healthSAN)
		if err != nil {
			return err
		}
		httpClient = controlhealth.NewHTTPClient(tlsCfg, *requestTimeout)
	}
	health, err := controlhealth.NewClient(*healthURL, httpClient)
	if err != nil {
		return err
	}

	restCfg, err := kubeConfig(*kubeconfig)
	if err != nil {
		return err
	}
	restCfg.UserAgent = controller.FieldManager
	kube, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return err
	}

	ctrl, err := controller.New(kube, health, controller.Config{
		Resync:       *resync,
		QueryTimeout: *requestTimeout,
		Logger:       logger,
	})
	if err != nil {
		return err
	}

	sourceID, err := sourceID()
	if err != nil {
		return err
	}
	go controller.RunLeaseReporter(ctx, health, controller.LeaseConfig{
		SourceID: sourceID,
		Version:  version,
		Interval: *leaseInterval,
		TTL:      *leaseTTL,
		Logger:   logger,
	}, func() string { return ctrl.ObservedState(*leaseTTL) })

	logger.Info("node-readiness starting", "source_id", sourceID, "version", version)
	return ctrl.Run(ctx, *workers)
}

func kubeConfig(path string) (*rest.Config, error) {
	if path != "" {
		return clientcmd.BuildConfigFromFlags("", path)
	}
	return rest.InClusterConfig()
}

// sourceID is the replica identity for the lease (COMMON: each replica has a different source_id).
func sourceID() (string, error) {
	if v := os.Getenv("POD_NAME"); v != "" {
		return v, nil
	}
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "", fmt.Errorf("cannot determine lease source_id: %v", err)
	}
	return h, nil
}
