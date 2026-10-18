//go:build integration

package main

// Local M3-1 end-to-end harness (tests/m3-1/run-local.sh). run() reads every
// credential from Google Secret Manager, which a laptop does not have. This
// test serves the same broker (broker.Service, store, the identity
// certificate bootstrap, the same TLS server settings) with one test-only
// change confined to this file: Secrets is localSecrets, which answers the
// one pinned version resource from a local file. It runs only when
// M31_BROKER_HARNESS_LISTEN is set and serves until SIGTERM.

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/broker"
	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/store"
	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/store/brokerdb"
	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/workloadcert"
)

// localSecrets serves exactly one secret version resource name from a file.
type localSecrets struct{ name, file string }

func (l localSecrets) Access(_ context.Context, name string) ([]byte, error) {
	if name != l.name {
		return nil, broker.ErrUnavailable
	}
	b, err := os.ReadFile(l.file)
	if err != nil || len(b) == 0 {
		return nil, broker.ErrUnavailable
	}
	return b, nil
}

func TestM31LocalBrokerHarness(t *testing.T) {
	listen := os.Getenv("M31_BROKER_HARNESS_LISTEN")
	if listen == "" {
		t.Skip("M31_BROKER_HARNESS_LISTEN not set (tests/m3-1/run-local.sh)")
	}
	if err := serveBrokerHarness(listen, os.Getenv("M31_BROKER_IDENTITY_URL"), os.Getenv("M31_BROKER_TOKEN_FILE"),
		os.Getenv("M31_BROKER_TLS_CA"), localSecrets{name: os.Getenv("M31_BROKER_SECRET_NAME"), file: os.Getenv("M31_BROKER_SECRET_FILE")}); err != nil {
		t.Fatal(err)
	}
}

func serveBrokerHarness(listen, identity, token, ca string, secrets localSecrets) error {
	if identity == "" || token == "" || ca == "" || secrets.name == "" || secrets.file == "" || os.Getenv("DATABASE_URL") == "" {
		return errors.New("identity url, token, ca, secret name/file and DATABASE_URL are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	config, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return err
	}
	defer pool.Close()
	allowed, err := brokerdb.New(pool).CheckPermissions(ctx)
	if err != nil || !allowed {
		return errors.New("broker database contract or permissions unavailable")
	}
	manager := &workloadcert.Manager{URL: identity, TokenFile: token, CAFile: ca, SAN: "spiffe://agentarium.internal/ns/agent-control/sa/credential-broker"}
	if err := manager.Refresh(ctx); err != nil {
		return err
	}
	tlsConfig, err := manager.ServerTLS()
	if err != nil {
		return err
	}
	go manager.Run(ctx, func() { log.Print("broker certificate renewal failed") })
	service := &broker.Service{Repo: store.Store{Queries: brokerdb.New(pool)}, Secrets: secrets, Observe: func(m broker.Metadata) {
		log.Printf("credential resolved resource=%q version=%q", m.Resource, m.Version)
	}, ObserveFailure: func(category string) { log.Printf("credential unavailable category=%q", category) }}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				service.PurgeExpired()
			}
		}
	}()
	server := &http.Server{Addr: listen, Handler: broker.Handler{Service: service}, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	server.SetKeepAlivesEnabled(false)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(sctx)
	}()
	log.Printf("broker harness listening on %s", listen)
	if err := server.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
