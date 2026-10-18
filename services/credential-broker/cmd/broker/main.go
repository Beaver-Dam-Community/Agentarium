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
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/broker"
	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/secrets"
	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/store"
	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/store/brokerdb"
	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/workloadcert"
	"github.com/jackc/pgx/v5/pgxpool"
	sm "google.golang.org/api/secretmanager/v1"
)

func run() error {
	listen := flag.String("listen", ":8443", "mTLS listen address")
	identity := flag.String("identity-url", "", "identity HTTPS origin")
	token := flag.String("bootstrap-token", "", "projected agentarium-identity token file")
	ca := flag.String("tls-ca", "", "identity trust bundle PEM file")
	flag.Parse()
	if *identity == "" || *token == "" || *ca == "" || os.Getenv("DATABASE_URL") == "" {
		return errors.New("identity-url, bootstrap-token, tls-ca and DATABASE_URL are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	config, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		return errors.New("invalid database configuration")
	}
	config.MaxConns = 10
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	config.ConnConfig.RuntimeParams["statement_timeout"] = "3000"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return errors.New("database initialization failed")
	}
	defer pool.Close()
	ready, cancel := context.WithTimeout(ctx, 5*time.Second)
	allowed, err := brokerdb.New(pool).CheckPermissions(ready)
	cancel()
	if err != nil || !allowed {
		return errors.New("broker database contract or permissions unavailable")
	}
	manager := &workloadcert.Manager{URL: *identity, TokenFile: *token, CAFile: *ca, SAN: "spiffe://agentarium.internal/ns/agent-control/sa/credential-broker"}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = manager.Refresh(call)
	cancel()
	if err != nil {
		return errors.New("certificate bootstrap failed")
	}
	tlsConfig, err := manager.ServerTLS()
	if err != nil {
		return errors.New("TLS initialization failed")
	}
	go manager.Run(ctx, func() { log.Print("broker certificate renewal failed") })
	api, err := sm.NewService(ctx)
	if err != nil {
		return errors.New("Secret Manager client initialization failed")
	}
	service := &broker.Service{Repo: store.Store{Queries: brokerdb.New(pool)}, Secrets: secrets.Google{Service: api}, Observe: func(m broker.Metadata) {
		log.Printf("credential resolved resource=%q version=%q", m.Resource, m.Version)
	}, ObserveFailure: func(category string) {
		log.Printf("credential unavailable category=%q", category)
	}}
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
	server := &http.Server{Addr: *listen, Handler: broker.Handler{Service: service}, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16384, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	server.SetKeepAlivesEnabled(false)
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("broker listener failed")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
