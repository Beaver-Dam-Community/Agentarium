package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/epoch"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/healthreport"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if err := run(); err != nil {
		log.Print("audit writer stopped: ", err)
		os.Exit(1)
	}
}
func run() error {
	listen := flag.String("listen", ":8443", "mTLS listen address")
	cert := flag.String("tls-cert", "", "server certificate PEM path")
	key := flag.String("tls-key", "", "server private key PEM path")
	ca := flag.String("tls-ca", "", "client trust bundle PEM path")
	sources := flag.String("sources", "", "trusted source registration JSON file")
	healthURL := flag.String("health-url", "", "control-health HTTPS origin")
	healthSource := flag.String("health-source-id", "", "registered audit-db source")
	version := flag.String("version", "", "deployed source version")
	bootstrapURL := flag.String("identity-url", "", "identity HTTPS origin for in-memory certificate bootstrap")
	bootstrapToken := flag.String("bootstrap-token", "", "projected agentarium-identity token file")
	lifecycle := flag.Bool("lifecycle", false, "enable installed lifecycle source/ingest/checkpoint contracts")
	lifecycleEpochDir := flag.String("lifecycle-epoch-dir", "", "persistent receiver instance/counter directory, exclusive per writer")
	lifecycleCIDRs := flag.String("lifecycle-node-cidrs", "", "comma-separated direct recorder node CIDRs")
	workEventsGateway := flag.String("work-events-gateway-san", "", "exact gateway service SAN allowed to relay runtime work events; empty disables "+ingest.WorkEventsPath)
	kernel := flag.Bool("kernel", false, "enable the installed kernel source/ingest contract (TASK-07 3.3)")
	kernelCIDRs := flag.String("kernel-node-cidrs", "", "comma-separated sensor exporter node CIDRs")
	flag.Parse()
	if *workEventsGateway != "" {
		if ns, _, ok := ingest.ParseServiceSAN(*workEventsGateway); !ok || ns == ingest.RuntimeNamespace {
			return errors.New("invalid --work-events-gateway-san")
		}
	}
	if *healthURL == "" || *healthSource == "" || *version == "" {
		return errors.New("health-url, health-source-id and version required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var managed *workloadcert.Manager
	var cfg *tls.Config
	var err error
	if *bootstrapURL != "" {
		managed = &workloadcert.Manager{URL: *bootstrapURL, TokenFile: *bootstrapToken, CAFile: *ca, SAN: "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"}
		call, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = managed.Refresh(call)
		cancel()
		if err == nil {
			cfg, err = managed.ServerTLS()
		}
		if err == nil {
			go managed.Run(ctx, func() { log.Print("service certificate renewal failed") })
		}
	} else {
		cfg, err = ingest.LoadTLS(*cert, *key, *ca)
	}
	if err != nil {
		return errors.New("cannot load TLS material")
	}
	raw, err := os.ReadFile(*sources)
	if err != nil {
		return errors.New("cannot read source registration")
	}
	var bindings []store.SourceBinding
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&bindings); err != nil {
		return errors.New("invalid source registration")
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errors.New("invalid database configuration")
	}
	pc.MaxConns = 10
	pc.ConnConfig.ConnectTimeout = 5 * time.Second
	pc.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
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
	authorizer, err := store.NewAuthorizer(pool, bindings)
	if err != nil {
		return err
	}
	var healthClient *http.Client
	if managed != nil {
		healthClient = managed.Client("spiffe://agentarium.internal/ns/agent-observe/sa/control-health", true)
	} else {
		healthClient, err = healthreport.Client(*healthURL, *cert, *key, *ca)
	}
	if err != nil {
		return errors.New("invalid health client configuration")
	}
	reporter := healthreport.Reporter{URL: *healthURL, SourceID: *healthSource, Version: *version, Client: healthClient, Check: func(ctx context.Context) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = tx.Rollback(cleanup)
		}()
		// An actual DB transaction must commit, not merely a TCP connection.
		var allowed bool
		if err := tx.QueryRow(ctx, "SELECT has_function_privilege(current_user,'audit.audit_append(jsonb,text[])','EXECUTE') AND pg_has_role(current_user,'audit_writer','MEMBER')").Scan(&allowed); err != nil {
			return err
		}
		if !allowed {
			return errors.New("audit role unavailable")
		}
		return tx.Commit(ctx)
	}}
	go reporter.Run(ctx, func() { log.Print("audit-db lease report failed") })
	auditStore := store.Store{Pool: pool, WriterVersion: *version}
	mux := http.NewServeMux()
	mux.Handle("/", ingest.Handler{Store: auditStore, Authorizer: authorizer})
	if *workEventsGateway != "" {
		mux.Handle(ingest.WorkEventsPath, ingest.WorkEventsHandler{GatewaySAN: *workEventsGateway, Store: auditStore})
	}
	parseCIDRs := func(list string) ([]netip.Prefix, error) {
		var prefixes []netip.Prefix
		if list == "" {
			return nil, nil
		}
		for _, text := range strings.Split(list, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(text))
			if err != nil {
				return nil, errors.New("invalid node CIDR")
			}
			prefixes = append(prefixes, prefix)
		}
		return prefixes, nil
	}
	if *lifecycle || *kernel {
		// One durable receiver epoch per writer process, shared by both streams.
		writerEpoch, releaseEpoch, err := epoch.Acquire(*lifecycleEpochDir)
		if err != nil {
			return errors.New("receiver durable epoch unavailable")
		}
		defer releaseEpoch()
		auditStore.WriterEpoch = writerEpoch
	}
	if *kernel {
		prefixes, err := parseCIDRs(*kernelCIDRs)
		if err != nil {
			return err
		}
		if err := authorizer.ValidateKernelConfiguration(prefixes); err != nil {
			return err
		}
		mux.Handle("/internal/kernel/events:batch", ingest.KernelHandler{Identity: authorizer, Validator: authorizer, Store: auditStore, NodeCIDRs: prefixes})
	}
	if *lifecycle {
		prefixes, err := parseCIDRs(*lifecycleCIDRs)
		if err != nil {
			return err
		}
		if err := authorizer.ValidateLifecycleConfiguration(prefixes); err != nil {
			return err
		}
		handler := ingest.LifecycleHandler{Identity: authorizer, Validator: authorizer, Store: auditStore, NodeCIDRs: prefixes}
		mux.Handle("/internal/lifecycle/events:batch", handler)
		mux.Handle("/internal/lifecycle/checkpoints", handler)
	}
	server := &http.Server{Addr: *listen, Handler: mux, TLSConfig: cfg,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second,
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
