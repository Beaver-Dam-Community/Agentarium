package dispatch

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service holds the coordinator's store and dependencies. Nil dependencies
// are treated as Unwired.
type Service struct {
	Pool      *pgxpool.Pool
	Policy    PolicySource
	Decisions DecisionSource
	Health    Health
	Audit     Auditor
	Leases    LeaseReporter
	Log       *slog.Logger
}

func (s *Service) policy() PolicySource {
	if s.Policy == nil {
		return Unwired{}
	}
	return s.Policy
}

func (s *Service) decisions() DecisionSource {
	if s.Decisions == nil {
		return Unwired{}
	}
	return s.Decisions
}

func (s *Service) health() Health {
	if s.Health == nil {
		return Unwired{}
	}
	return s.Health
}

func (s *Service) audit() Auditor {
	if s.Audit == nil {
		return Unwired{}
	}
	return s.Audit
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// inTx runs fn in a READ COMMITTED transaction (TASK-03 3.2 lock order) that
// waits at most LockTimeout for a row lock; a longer wait is 503
// LOCK_TIMEOUT and nothing is committed.
func (s *Service) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '"+LockTimeout+"'"); err != nil {
			return err
		}
		return fn(tx)
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" { // lock_not_available
		return unavailable("LOCK_TIMEOUT", "row lock wait exceeded "+LockTimeout)
	}
	return err
}

// Authenticate maps a verified client certificate to an adapter. The
// certificate's serial must match an unrevoked, unexpired
// identity.issued_certificates row with the same SAN, issued to a registered,
// enabled adapter workload with a recorded node and boot (TASK-03 3.3.1: the
// coordinator checks revoked_at on every request).
func (s *Service) Authenticate(ctx context.Context, leaf *x509.Certificate) (Adapter, error) {
	if leaf == nil || len(leaf.URIs) != 1 || leaf.SerialNumber == nil {
		return Adapter{}, fail(http.StatusUnauthorized, "AUTH_REQUIRED", "client certificate needs one URI SAN")
	}
	san := leaf.URIs[0].String()
	ns, ksa, err := parseSAN(san)
	if err != nil {
		return Adapter{}, fail(http.StatusUnauthorized, "AUTH_REQUIRED", err.Error())
	}
	a := Adapter{SAN: san}
	err = s.Pool.QueryRow(ctx, `
SELECT w.adapter_id, c.node_uid::text, c.boot_id
FROM identity.issued_certificates c
JOIN identity.registered_workloads w USING (namespace, ksa)
WHERE c.serial = $1 AND c.san_uri = $2 AND c.namespace = $3 AND c.ksa = $4
  AND c.revoked_at IS NULL AND c.expires_at > statement_timestamp()
  AND w.role = 'adapter' AND w.enabled
  AND c.node_uid IS NOT NULL AND c.boot_id IS NOT NULL`,
		hex.EncodeToString(leaf.SerialNumber.Bytes()), san, ns, ksa).Scan(&a.AdapterID, &a.NodeUID, &a.BootID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Adapter{}, fail(http.StatusUnauthorized, "AUTH_REQUIRED", "certificate is not a current adapter certificate")
	}
	if err != nil {
		return Adapter{}, err
	}
	return a, nil
}

// parseSAN reads spiffe://agentarium.internal/ns/<ns>/sa/<ksa>[/pod/<uid>].
func parseSAN(san string) (string, string, error) {
	rest, ok := strings.CutPrefix(san, "spiffe://agentarium.internal/ns/")
	if !ok {
		return "", "", fmt.Errorf("SAN %q is not a workload SAN", san)
	}
	p := strings.Split(rest, "/")
	if !(len(p) == 3 || len(p) == 5) || p[1] != "sa" || p[0] == "" || p[2] == "" ||
		(len(p) == 5 && (p[3] != "pod" || p[4] == "")) {
		return "", "", fmt.Errorf("SAN %q is malformed", san)
	}
	return p[0], p[2], nil
}

// depErr maps a dependency failure: an *Error passes through, and so does a
// lock timeout (55P03) so that inTx answers LOCK_TIMEOUT; anything else
// becomes 503 with code.
func depErr(err error, code, what string) error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
		return err
	}
	return unavailable(code, what+": "+err.Error())
}
