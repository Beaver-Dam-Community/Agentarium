package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/epoch"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/store"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/workloadcert"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	if err := run(); err != nil {
		log.Print("control-health stopped: ", err)
		os.Exit(1)
	}
}
func run() error {
	listen := flag.String("listen", ":8443", "mTLS listener")
	cert := flag.String("tls-cert", "", "certificate PEM")
	key := flag.String("tls-key", "", "key PEM")
	ca := flag.String("tls-ca", "", "trust bundle PEM")
	profile := flag.String("profile", "", "trusted profile JSON")
	bootstrapURL := flag.String("identity-url", "", "identity HTTPS origin for in-memory certificate bootstrap")
	bootstrapToken := flag.String("bootstrap-token", "", "projected agentarium-identity token file")
	epochDir := flag.String("epoch-dir", "", "persistent producer epoch directory")
	startupCapture := flag.String("startup-capture", "", "mounted control-health-startup-capture file; empty keeps new boot registration disabled")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var tlsConfig *tls.Config
	var err error
	if *bootstrapURL != "" {
		managed := &workloadcert.Manager{URL: *bootstrapURL, TokenFile: *bootstrapToken, CAFile: *ca, SAN: "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"}
		call, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = managed.Refresh(call)
		cancel()
		if err == nil {
			tlsConfig, err = managed.ServerTLS()
		}
		if err == nil {
			go managed.Run(ctx, func() { log.Print("service certificate renewal failed") })
		}
	} else {
		tlsConfig, err = health.LoadTLS(*cert, *key, *ca)
	}
	if err != nil {
		return errors.New("cannot load TLS material")
	}
	raw, err := os.ReadFile(*profile)
	if err != nil {
		return errors.New("cannot load profile")
	}
	var cfg store.Config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil {
		return errors.New("invalid profile")
	}
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
	pc.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	pc.ConnConfig.RuntimeParams["lock_timeout"] = "2000"
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return errors.New("database initialization failed")
	}
	defer pool.Close()
	backend, err := store.New(pool, cfg)
	if err != nil {
		return err
	}
	producerEpoch, releaseEpoch, err := epoch.Acquire(*epochDir)
	if err != nil {
		return err
	}
	defer releaseEpoch()
	backend.Epoch = producerEpoch
	if raw, err := os.ReadFile(*startupCapture); *startupCapture != "" && errors.Is(err, fs.ErrNotExist) {
		// The ConfigMap is optional until the installer records startup_capture
		// in the lock; without it every new boot registration stays rejected.
		log.Print("startup_capture not installed; new node boot registration disabled")
	} else if *startupCapture != "" {
		// NodeFacts: trusted lock rows plus fresh Node get/list (TASK-06 3.2).
		if err != nil {
			return errors.New("cannot load startup_capture")
		}
		rows, err := store.ParseStartupCapture(raw)
		if err != nil {
			return err
		}
		kube, err := rest.InClusterConfig()
		if err != nil {
			return errors.New("in-cluster Kubernetes configuration unavailable")
		}
		// Concurrent first reports (pool upgrade) each LIST Nodes within a 2s
		// bootstrap budget; raise client-go's default 5 QPS / burst 10.
		kube.QPS, kube.Burst = 20, 40
		client, err := kubernetes.NewForConfig(kube)
		if err != nil {
			return err
		}
		backend.NodeFacts = store.KubeNodeFacts{Client: client, Rows: rows}
	}
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(check)
	cancel()
	if err != nil {
		return errors.New("database unavailable")
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				call, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := backend.Expire(call)
				cancel()
				if err != nil {
					log.Print("lease expiry transaction failed")
				}
				call, cancel = context.WithTimeout(ctx, 5*time.Second)
				err = backend.Recover(call)
				cancel()
				if err != nil {
					log.Print("hold recovery transaction failed")
				}
				call, cancel = context.WithTimeout(ctx, 5*time.Second)
				err = backend.RecordNetpolGaps(call)
				cancel()
				if err != nil {
					log.Print("netpol collection gap transaction failed")
				}
			}
		}
	}()
	server := &http.Server{Addr: *listen, Handler: health.Handler{Backend: backend, Workers: backend}, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16384, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
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
