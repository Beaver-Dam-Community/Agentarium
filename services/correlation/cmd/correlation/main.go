// Command correlation is the TASK-10 connector service: the netpol collector
// batch receiver and the correlation worker, NetworkFinding and risk-event
// loops. Installation inputs are the environment lock, the network values and
// the TASK-06 allow matrix mounted read-only; nothing is injected.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/epoch"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/receiver"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/results"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/risk"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/service"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/sources"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/worker"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/workloadcert"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/netpol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	selfSAN          = "spiffe://agentarium.internal/ns/agent-observe/sa/correlation"
	controlHealthSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"
)

func main() {
	if err := run(); err != nil {
		log.Print("correlation stopped: ", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":8443", "mTLS listener")
	ca := flag.String("tls-ca", "", "trust bundle PEM")
	identityURL := flag.String("identity-url", "", "identity HTTPS origin for in-memory certificate bootstrap")
	token := flag.String("bootstrap-token", "", "projected agentarium-identity token file")
	clusterUID := flag.String("cluster-uid", "", "installation cluster UID")
	lock := flag.String("environment-lock", "", "environment lock JSON (read-only mount)")
	values := flag.String("network-values", "", "network values JSON (read-only mount)")
	matrix := flag.String("allow-matrix", "", "TASK-06 allow matrix JSON (read-only mount)")
	healthURL := flag.String("control-health-url", "", "control-health HTTPS origin")
	auditSource := flag.String("audit-source-id", "", "registered correlation audit source")
	version := flag.String("version", "", "deployed source version")
	epochDir := flag.String("epoch-dir", "", "persistent audit source epoch directory")
	protected := flag.String("protected-paths", "/work/protected-fixture", "comma-separated TASK-09 protected paths")
	interval := flag.Duration("interval", 30*time.Second, "evaluation cadence")
	lookback := flag.Duration("lookback", 15*time.Minute, "recent join re-evaluation lookback; retained pending inputs are always replayed")
	flag.Parse()
	cluster, err := uuid.Parse(*clusterUID)
	if err != nil || cluster == uuid.Nil || *identityURL == "" || *healthURL == "" || *auditSource == "" || *version == "" {
		return errors.New("cluster-uid, identity-url, control-health-url, audit-source-id and version required")
	}
	in, err := sources.ReadInputs(*lock, *values, *matrix)
	if err != nil {
		return err
	}
	table, env, err := sources.Build(in)
	if err != nil {
		return err
	}
	classifier, err := netpol.NewClassifier(env)
	if err != nil {
		return errors.New("invalid segment classifier inputs")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	managed := &workloadcert.Manager{URL: *identityURL, TokenFile: *token, CAFile: *ca, SAN: selfSAN}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = managed.Refresh(call)
	cancel()
	var tlsConfig *tls.Config
	if err == nil {
		tlsConfig, err = managed.ServerTLS()
	}
	if err != nil {
		return errors.New("cannot load TLS material")
	}
	go managed.Run(ctx, func() { log.Print("service certificate renewal failed") })
	sourceEpoch, release, err := epoch.Acquire(*epochDir)
	if err != nil {
		return errors.New("durable epoch unavailable")
	}
	defer release()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL required")
	}
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errors.New("invalid database configuration")
	}
	pc.MaxConns = 10
	pc.ConnConfig.ConnectTimeout = 5 * time.Second
	pc.ConnConfig.RuntimeParams["statement_timeout"] = "10000"
	pc.ConnConfig.RuntimeParams["lock_timeout"] = "2000"
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return errors.New("database initialization failed")
	}
	defer pool.Close()
	ready, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(ready)
	cancel()
	if err != nil {
		return errors.New("database unavailable")
	}

	certs := sources.Workloads{Pool: pool}
	if !certs.Available(ctx) {
		log.Print("identity.pod_workloads unavailable (TASK-03 #206): workloads resolve unknown, findings stay unlinked and no risk hold is requested")
	}
	resolve := func(pod uuid.UUID) *string {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return certs.Resolve(c, pod)
	}
	netpolStore := netpol.Store{Pool: pool, Config: netpol.Config{SourceID: *auditSource, Version: *version, Epoch: sourceEpoch}, Classifier: classifier}
	paths := []string{}
	for _, p := range strings.Split(*protected, ",") {
		if p = strings.TrimSpace(p); p != "" {
			paths = append(paths, p)
		}
	}
	loop := &service.Loop{
		Nodes: service.PoolNodes(pool),
		Queue: &service.PoolQueue{Pool: pool},
		Worker: worker.Worker{Pool: pool, Results: results.Store{Pool: pool, Config: results.Config{SourceID: *auditSource, Version: *version, Epoch: sourceEpoch, Tenant: "*"}},
			ClusterUID: cluster, AlgorithmVersion: "tuple-v1", Workloads: resolve},
		Netpol: service.NetpolEvaluator{Store: netpolStore, Workloads: resolve, Allowed: table.NetpolAllowed},
		Risk: service.RiskEvaluator{Pool: pool, Workloads: resolve, Allowed: table.RiskAllowed,
			Config: risk.Config{ProtectedPaths: paths}, Holds: risk.HoldClient{URL: strings.TrimRight(*healthURL, "/"), Client: managed.Client(controlHealthSAN, true)}},
		Interval: *interval,
		Start:    time.Now().UTC().Add(-*lookback),
	}
	go loop.Run(ctx)

	mux := http.NewServeMux()
	mux.Handle(receiver.Path, receiver.Handler{ClusterUID: cluster, Identity: receiver.PoolIdentity{Pool: pool}, Store: netpolStore})
	server := &http.Server{Addr: *listen, Handler: mux, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 10 * time.Second,
		MaxHeaderBytes: 16384, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	server.SetKeepAlivesEnabled(false)
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTPS listener failed")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
