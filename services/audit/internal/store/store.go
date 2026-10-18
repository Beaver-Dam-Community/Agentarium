// Package store connects business-event ingress to SECURITY DEFINER functions.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	Pool          *pgxpool.Pool
	WriterVersion string
	WriterEpoch   string
}

func (s Store) Append(ctx context.Context, event ingest.Event, raw []byte) (ingest.Ack, error) {
	ack := ingest.Ack{EventID: event.EventID}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ack, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	q := auditdb.New(tx)
	result, err := q.AppendEvent(ctx, raw)
	if err != nil {
		return ack, classify(err)
	}
	ack.Result = result
	if result == "conflict" {
		if err := tx.Rollback(ctx); err != nil {
			return ack, err
		}
		// The business transaction has ended. This autocommit survives its rollback.
		_, err := auditdb.New(s.Pool).RecordConflict(ctx, auditdb.RecordConflictParams{EventID: event.EventID, Digest: event.PayloadDigest, SourceID: event.SourceID})
		return ack, classify(err)
	}
	if result != "created" && result != "duplicate" {
		return ack, errors.New("invalid append result")
	}
	var id pgtype.UUID
	if err := id.Scan(event.EventID); err != nil {
		return ack, ingest.ErrSchema
	}
	received, err := q.EventAck(ctx, auditdb.EventAckParams{EventID: id, SourceID: event.SourceID, Tenant: event.Tenant})
	if err != nil {
		return ack, classify(err)
	}
	if !received.Valid || received.InfinityModifier != pgtype.Finite {
		return ack, errors.New("invalid ack timestamp")
	}
	ack.ReceivedAt = received.Time
	if err := tx.Commit(ctx); err != nil {
		return ack, err
	}
	return ack, nil
}
func classify(err error) error {
	if err == nil {
		return nil
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		switch pgerr.Code {
		case "42501":
			return ingest.ErrForbidden
		case "22023", "22P02", "22P05", "22007", "22008", "23502", "23514":
			return ingest.ErrSchema
		}
	}
	return err
}

// SourceBinding is trusted installation configuration, not request data.
// It maps one source to its registered principal; replicas sharing a service
// certificate are the same security principal in the COMMON PKI contract.
type SourceBinding struct {
	SourceID  string   `json:"source_id"`
	Namespace string   `json:"namespace"`
	KSA       string   `json:"ksa"`
	Principal string   `json:"principal"`
	Scopes    []string `json:"scopes,omitempty"`
}
type Authorizer struct {
	Pool     *pgxpool.Pool
	bindings map[string]SourceBinding
}

func NewAuthorizer(pool *pgxpool.Pool, bindings []SourceBinding) (*Authorizer, error) {
	a := &Authorizer{Pool: pool, bindings: map[string]SourceBinding{}}
	for _, b := range bindings {
		_, _, ok := ingest.ParseServiceSAN("spiffe://agentarium.internal/ns/" + b.Namespace + "/sa/" + b.KSA)
		if b.SourceID == "" || b.Principal == "" || !ok || b.Namespace == "agent-exec" {
			return nil, errors.New("invalid source registration")
		}
		if _, exists := a.bindings[b.SourceID]; exists {
			return nil, fmt.Errorf("duplicate source registration")
		}
		a.bindings[b.SourceID] = b
	}
	return a, nil
}
func (a *Authorizer) Authorize(ctx context.Context, san, source string) error {
	b, ok := a.bindings[source]
	if !ok {
		return ingest.ErrForbidden
	}
	ns, ksa, ok := ingest.ParseServiceSAN(san)
	if !ok || ns != b.Namespace || ksa != b.KSA {
		return ingest.ErrForbidden
	}
	registered, err := auditdb.New(a.Pool).RegisteredProducer(ctx, auditdb.RegisteredProducerParams{Namespace: ns, Ksa: ksa, Principal: b.Principal})
	if err != nil {
		return err
	}
	if !registered {
		return ingest.ErrForbidden
	}
	return nil
}
