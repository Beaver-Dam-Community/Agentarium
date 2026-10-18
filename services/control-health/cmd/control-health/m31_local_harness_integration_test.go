//go:build integration

package main

// Local M3-1 end-to-end harness (tests/m3-1/run-local.sh). With
// --startup-capture, run() reads the current Node UID/boot from the
// in-cluster Kubernetes API (store.KubeNodeFacts), which a laptop does not
// have. This test serves the same control-health (identity certificate
// bootstrap, profile, store.Store, the expiry/recovery loop, health.Handler,
// the same TLS server settings) with one test-only change confined to this
// file: NodeFacts is harnessNodes, a fixed table of local nodes answering
// what KubeNodeFacts would read from the Node object and the lock's
// startup_capture row (unsupported / not_measured).
//
// It runs only when M31_HEALTH_HARNESS_CONFIG names a JSON config file and
// serves until SIGTERM.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/epoch"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/store"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/workloadcert"
)

type healthHarnessConfig struct {
	Listen         string            `json:"listen"`
	IdentityURL    string            `json:"identity_url"`
	BootstrapToken string            `json:"bootstrap_token"`
	TLSCA          string            `json:"tls_ca"`
	Profile        string            `json:"profile"`
	EpochDir       string            `json:"epoch_dir"`
	Nodes          map[string]string `json:"nodes"` // node UID -> current boot ID
}

// harnessNodes is the fixed Node table (node UID -> boot ID).
type harnessNodes map[string]string

func (h harnessNodes) Current(_ context.Context, node string) (store.NodeFacts, error) {
	boot, ok := h[node]
	if !ok {
		return store.NodeFacts{}, errors.New("unknown node")
	}
	return store.NodeFacts{NodeUID: node, BootID: boot, StartupCapture: health.StartupUnsupported, StartupMeasurement: store.NotMeasured}, nil
}

func TestM31LocalHealthHarness(t *testing.T) {
	path := os.Getenv("M31_HEALTH_HARNESS_CONFIG")
	if path == "" {
		t.Skip("M31_HEALTH_HARNESS_CONFIG not set (tests/m3-1/run-local.sh)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c healthHarnessConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		t.Fatal(err)
	}
	if err := serveHealthHarness(c); err != nil {
		t.Fatal(err)
	}
}

func serveHealthHarness(c healthHarnessConfig) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	managed := &workloadcert.Manager{URL: c.IdentityURL, TokenFile: c.BootstrapToken, CAFile: c.TLSCA, SAN: "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := managed.Refresh(call)
	cancel()
	if err != nil {
		return err
	}
	tlsConfig, err := managed.ServerTLS()
	if err != nil {
		return err
	}
	go managed.Run(ctx, func() { log.Print("service certificate renewal failed") })
	raw, err := os.ReadFile(c.Profile)
	if err != nil {
		return err
	}
	var cfg store.Config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return err
	}
	pc, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	pc.MaxConns = 10
	pc.ConnConfig.ConnectTimeout = 5 * time.Second
	pc.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	pc.ConnConfig.RuntimeParams["lock_timeout"] = "2000"
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return err
	}
	defer pool.Close()
	backend, err := store.New(pool, cfg)
	if err != nil {
		return err
	}
	producerEpoch, releaseEpoch, err := epoch.Acquire(c.EpochDir)
	if err != nil {
		return err
	}
	defer releaseEpoch()
	backend.Epoch = producerEpoch
	backend.NodeFacts = harnessNodes(c.Nodes)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for name, f := range map[string]func(context.Context) error{"lease expiry": backend.Expire, "hold recovery": backend.Recover, "netpol collection gap": backend.RecordNetpolGaps} {
					call, cancel := context.WithTimeout(ctx, 5*time.Second)
					if err := f(call); err != nil {
						log.Printf("%s transaction failed: %v", name, err)
					}
					cancel()
				}
			}
		}
	}()
	server := &http.Server{Addr: c.Listen, Handler: health.Handler{Backend: backend, Workers: backend}, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16384, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	server.SetKeepAlivesEnabled(false)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(sctx)
	}()
	log.Printf("control-health harness listening on %s", c.Listen)
	if err := server.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
