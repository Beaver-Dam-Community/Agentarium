// Command probe-runner is the TASK-10 3.2 answer probe runner: one long-lived
// Pod per node (DaemonSet) in agent-exec and agent-adapters. It obtains a
// Pod-bound clientAuth certificate, gives the process/tcp/file stimuli every
// 60 seconds and reports each one 25 seconds later.
//
// The agent-exec admission profile allows no args and no valueFrom env, so
// every setting is a plain environment value:
//
//	AGENTARIUM_TOKEN_FILE         projected agentarium-identity token (default /run/agentarium/identity/token)
//	AGENTARIUM_TRUST_BUNDLE_PEM   CA bundle PEM text (required)
//	AGENTARIUM_BOOTSTRAP_URL      https origin for /internal/workload-certificates (required):
//	                              the gateway in agent-exec, workload-identity in agent-adapters
//	AGENTARIUM_REPORT_URL         https origin for results (required): the gateway relay
//	                              /v1/runtime/probe-reports in agent-exec, control-health
//	                              /internal/control-health/probe-results in agent-adapters
//	AGENTARIUM_PROBE_SINK         host:port of agent-targets/probe-sink (required)
//	AGENTARIUM_PROBE_MARKER       marker binary (default /probe/bin/marker)
//	AGENTARIUM_PROBE_FIXTURE      protected fixture (default /work/protected-fixture)
//
// The namespace comes from the token, and fixes the peers: in agent-exec
// both peers are the gateway (TASK-06: its only egress besides probe-sink).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/probe-runner/internal/probe"
	"github.com/Beaver-Dam-Community/Agentarium/services/probe-runner/internal/workload"
)

// Service identities (COMMON service PKI).
const (
	gatewaySAN  = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"
	identitySAN = "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity"
	healthSAN   = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"
	bootIDPath  = "/proc/sys/kernel/random/boot_id"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := run(ctx, logger); err != nil {
		logger.Error("probe-runner exited", "error", err.Error())
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func run(ctx context.Context, logger *slog.Logger) error {
	tokenFile := env("AGENTARIUM_TOKEN_FILE", "/run/agentarium/identity/token")
	self, err := workload.ReadSelf(tokenFile)
	if err != nil {
		return err
	}
	boot, err := workload.ReadBootID(bootIDPath)
	if err != nil {
		return err
	}
	roots, err := workload.Roots(os.Getenv("AGENTARIUM_TRUST_BUNDLE_PEM"))
	if err != nil {
		return err
	}
	bootstrapURL, err := workload.Origin(os.Getenv("AGENTARIUM_BOOTSTRAP_URL"))
	if err != nil {
		return fmt.Errorf("AGENTARIUM_BOOTSTRAP_URL: %w", err)
	}
	reportURL, err := workload.Origin(os.Getenv("AGENTARIUM_REPORT_URL"))
	if err != nil {
		return fmt.Errorf("AGENTARIUM_REPORT_URL: %w", err)
	}
	sink := os.Getenv("AGENTARIUM_PROBE_SINK")
	if sink == "" {
		return errors.New("AGENTARIUM_PROBE_SINK is required")
	}
	bootstrapSAN, reportSAN, path := gatewaySAN, gatewaySAN, probe.RelayPath
	if self.Namespace == workload.AdaptersNamespace {
		bootstrapSAN, reportSAN, path = identitySAN, healthSAN, probe.DirectPath
	}
	certs := &workload.Certs{TokenFile: tokenFile, Roots: roots, URL: bootstrapURL,
		Client: workload.NewClient(roots, bootstrapSAN, nil), SAN: self.SAN()}
	for {
		err := certs.Refresh(ctx)
		if err == nil {
			break
		}
		logger.Warn("certificate bootstrap failed", "error", err.Error())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	logger.Info("probe runner ready", "namespace", self.Namespace, "node", self.NodeName, "node_uid", self.NodeUID, "boot_id", boot, "san", self.SAN())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	expired := make(chan struct{})
	go certs.Run(ctx, 30*time.Second, func(err error) { logger.Warn("certificate renewal failed", "error", err.Error()) }, func() { close(expired) })
	sender := probe.Sender{URL: reportURL, Path: path, Client: workload.NewClient(roots, reportSAN, certs.GetClientCertificate)}
	runner := &probe.Runner{NodeUID: self.NodeUID, BootID: boot, Send: sender.Send, Log: logger,
		Stimuli: map[string]probe.Stimulus{
			"process": probe.Marker(env("AGENTARIUM_PROBE_MARKER", probe.DefaultMarker)),
			"tcp":     probe.Connect(sink),
			"file":    probe.Fixture(env("AGENTARIUM_PROBE_FIXTURE", probe.DefaultFixture)),
		}}
	done := make(chan struct{})
	go func() {
		runner.Run(ctx)
		close(done)
	}()
	select {
	case <-expired:
		cancel()
		<-done
		return errors.New("workload certificate expired without renewal")
	case <-done:
		return nil
	}
}
