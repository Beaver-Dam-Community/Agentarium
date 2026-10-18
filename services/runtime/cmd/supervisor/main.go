// Command supervisor is the agent-exec container's fixed entrypoint
// (/app/bin/agent-runtime, TASK-01 agent-exec admission runtimeCommand): the
// trusted supervisor of the minimal M3-1 runtime (TASK-15). It is PID 1 of
// the container and handles one session, then exits.
//
// The admission policy forbids container args and env valueFrom, so every
// setting is a plain environment variable; each flag defaults to its
// variable (flags are for local runs).
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/certs"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/gwclient"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/isolation"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/procinfo"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/spawn"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/supervisor"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/worker"
)

type config struct {
	mode                          string
	gatewayURL, gatewaySAN        string
	trustFile, trustPEM           string
	tokenFile, workerPath         string
	scratchRoot, namespace, ksa   string
	maxWorkers                    int
	targetID, summary, email      string
	version                       string
	assignmentTimeout             time.Duration
	approvalPoll, approvalTimeout time.Duration
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(k); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		fmt.Fprintf(os.Stderr, "agent-runtime: %s=%q is not a duration\n", k, v)
		os.Exit(2)
	}
	return def
}

func parse(args []string) (config, error) {
	var c config
	fs := flag.NewFlagSet("agent-runtime", flag.ContinueOnError)
	fs.StringVar(&c.mode, "mode", env("AGENTARIUM_RUNTIME_MODE", "demo"), "demo or adk (fixed Python worker)")
	fs.StringVar(&c.gatewayURL, "gateway-url", env("AGENTARIUM_GATEWAY_URL", ""), "policy gateway https origin, port 8443 (required)")
	fs.StringVar(&c.gatewaySAN, "gateway-san", env("AGENTARIUM_GATEWAY_SAN", gwclient.DefaultGatewaySAN), "expected gateway URI SAN")
	fs.StringVar(&c.trustFile, "trust-bundle-file", env("AGENTARIUM_TRUST_BUNDLE_FILE", ""), "PEM trust bundle file (one of -trust-bundle-file, -trust-bundle-pem)")
	fs.StringVar(&c.trustPEM, "trust-bundle-pem", env("AGENTARIUM_TRUST_BUNDLE_PEM", ""), "PEM trust bundle value")
	fs.StringVar(&c.tokenFile, "token-file", env("AGENTARIUM_TOKEN_FILE", "/run/agentarium/identity/token"), "projected token, audience agentarium-identity")
	fs.StringVar(&c.workerPath, "worker-path", env("AGENTARIUM_WORKER_PATH", "/app/bin/agent-worker"), "approved worker executable (exporter worker_binaries)")
	fs.StringVar(&c.scratchRoot, "scratch-root", env("AGENTARIUM_SCRATCH_ROOT", "/work"), "session scratch root")
	fs.StringVar(&c.namespace, "namespace", env("AGENTARIUM_NAMESPACE", "agent-exec"), "namespace the issued SAN must name")
	fs.StringVar(&c.ksa, "ksa", env("AGENTARIUM_KSA", "agent-runtime"), "KSA the issued SAN must name")
	mw, _ := strconv.Atoi(env("AGENTARIUM_MAX_CONCURRENT_WORKERS", "0"))
	fs.IntVar(&c.maxWorkers, "max-concurrent-workers", mw, "max_concurrent_workers install input (required; this runtime supports 1)")
	fs.StringVar(&c.targetID, "demo-target-id", env("AGENTARIUM_DEMO_TARGET_ID", "receiver-primary"), "receiver.submit target_id")
	fs.StringVar(&c.version, "source-version", env("AGENTARIUM_RUNTIME_VERSION", ""), "deployed runtime version, source_version of agent_work_* reports (required)")
	fs.StringVar(&c.summary, "demo-summary", env("AGENTARIUM_DEMO_SUMMARY", ""), "receiver.submit payload.summary (required)")
	fs.StringVar(&c.email, "demo-email", env("AGENTARIUM_DEMO_EMAIL", ""), "receiver.submit payload.email (empty: null)")
	fs.DurationVar(&c.assignmentTimeout, "assignment-timeout", envDuration("AGENTARIUM_ASSIGNMENT_TIMEOUT", 0), "give up waiting for an assignment (0: never)")
	fs.DurationVar(&c.approvalPoll, "approval-poll", envDuration("AGENTARIUM_APPROVAL_POLL", 15*time.Second), "interval of resume :reevaluate attempts while approval is pending")
	fs.DurationVar(&c.approvalTimeout, "approval-timeout", envDuration("AGENTARIUM_APPROVAL_TIMEOUT", 10*time.Minute), "give up waiting for approval")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, errors.New("unexpected arguments")
	}
	switch {
	case c.gatewayURL == "":
		return c, errors.New("-gateway-url / AGENTARIUM_GATEWAY_URL is required")
	case (c.trustFile == "") == (c.trustPEM == ""):
		return c, errors.New("exactly one of -trust-bundle-file and -trust-bundle-pem is required")
	case c.maxWorkers != 1:
		// TASK-15: max_concurrent_workers is a required install input; this
		// minimal runtime handles exactly one session worker.
		return c, errors.New("-max-concurrent-workers / AGENTARIUM_MAX_CONCURRENT_WORKERS must be set to 1")
	case c.mode != "demo" && c.mode != "adk":
		return c, errors.New("runtime mode must be demo or adk")
	case c.mode == "demo" && c.summary == "":
		return c, errors.New("-demo-summary / AGENTARIUM_DEMO_SUMMARY is required")
	case c.version == "":
		return c, errors.New("-source-version / AGENTARIUM_RUNTIME_VERSION is required")
	}
	return c, nil
}

func main() {
	// Protect memory before reading credentials or starting any worker.
	if err := isolation.ProtectSupervisor(); err != nil {
		fmt.Fprintln(os.Stderr, "agent-runtime:", err)
		os.Exit(1)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	c, err := parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-runtime:", err)
		os.Exit(2)
	}
	syscall.Umask(0o077) // TASK-15 file hygiene; inherited by the worker
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	out, err := run(ctx, c, log)
	b, _ := json.Marshal(out)
	fmt.Fprintf(os.Stdout, "%s\n", b)
	if err != nil {
		log.Error("run failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, c config, log *slog.Logger) (supervisor.Outcome, error) {
	epoch := uuid.NewString()
	out := supervisor.Outcome{RuntimeProcessEpoch: epoch}
	pem := []byte(c.trustPEM)
	if c.trustFile != "" {
		b, err := os.ReadFile(c.trustFile)
		if err != nil {
			return out, err
		}
		pem = b
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return out, errors.New("trust bundle has no certificate")
	}
	digest, err := isolation.Digest()
	if err != nil {
		return out, err
	}
	m := &certs.Manager{TokenFile: c.tokenFile, Roots: roots, Namespace: c.namespace, KSA: c.ksa}
	gw, err := gwclient.New(c.gatewayURL, roots, c.gatewaySAN, m.GetClientCertificate)
	if err != nil {
		return out, err
	}
	for {
		if err = m.Refresh(ctx, gw); err == nil {
			break
		}
		log.Warn("certificate bootstrap failed; retrying", "err", err)
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	log.Info("workload certificate issued", "san", m.SAN(), "renew_at", m.RenewAt())
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go m.Run(ctx, gw, 5*time.Second, func(err error) { cancel(fmt.Errorf("certificate expired: %w", err)) })

	var email *string
	if c.email != "" {
		email = &c.email
	}
	operations := []string{worker.OperationReceiverSubmit}
	var workerArgs []string
	if c.mode == "adk" {
		if c.workerPath == "/app/bin/agent-worker" {
			c.workerPath = "/app/venv/bin/python"
		}
		workerArgs = []string{"-I", "-m", "agentarium_runtime.worker"}
		operations = []string{canonical.OpModelGenerate, canonical.OpK8sPodsList, canonical.OpK8sEventsList, canonical.OpK8sPodsLogs, worker.OperationReceiverSubmit}
	}
	s := &supervisor.Supervisor{
		GW:    gw,
		Spawn: spawn.Exec{Path: c.workerPath, Args: workerArgs, ScratchRoot: c.scratchRoot, Log: log},
		Epoch: epoch,
		Log:   log,
		Cfg: supervisor.Config{
			Task:                   supervisor.Task{TargetID: c.targetID, Summary: c.summary, Email: email},
			AllowedOperations:      operations,
			IsolationProfileDigest: digest,
			Hint:                   func(pid int) (procinfo.Hint, error) { return procinfo.Of("/proc", pid) },
			SupervisorPID:          os.Getpid(),
			SourceVersion:          c.version,
			AssignmentTimeout:      c.assignmentTimeout,
			ApprovalPoll:           c.approvalPoll,
			ApprovalTimeout:        c.approvalTimeout,
		},
	}
	return s.Run(ctx)
}
