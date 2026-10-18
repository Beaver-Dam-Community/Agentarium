// Package store is the identity schema access of M1-2 on PostgreSQL (pgx v5).
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/bootstrap"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/pki"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/revoker"
)

// Store implements bootstrap.Store and the revocation queries.
type Store struct{ Pool *pgxpool.Pool }

func (s Store) Workload(ctx context.Context, namespace, ksa string) (bootstrap.Workload, bool, error) {
	var role string
	var enabled bool
	err := s.Pool.QueryRow(ctx,
		`SELECT role, enabled FROM identity.registered_workloads WHERE namespace = $1 AND ksa = $2`,
		namespace, ksa).Scan(&role, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return bootstrap.Workload{}, false, nil
	}
	if err != nil {
		return bootstrap.Workload{}, false, err
	}
	return bootstrap.Workload{Namespace: namespace, KSA: ksa, Role: pki.Role(role), Enabled: enabled}, true, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s Store) RecordIssued(ctx context.Context, r bootstrap.IssuedRecord) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO identity.issued_certificates
		   (serial, san_uri, namespace, ksa, pod_uid, node_uid, boot_id, issued_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5::uuid, $6::uuid, $7, $8, $9)`,
		r.Serial, r.SAN, r.Namespace, r.KSA, nullable(r.PodUID), nullable(r.NodeUID), nullable(r.BootID), r.IssuedAt, r.ExpiresAt)
	return err
}

// RevokePod marks every unrevoked certificate of a Pod revoked
// (TASK-03 3.3.1: the gateway and coordinator check revoked_at IS NULL).
func (s Store) RevokePod(ctx context.Context, podUID string, at time.Time) (int64, error) {
	tag, err := s.Pool.Exec(ctx,
		`UPDATE identity.issued_certificates SET revoked_at = $2
		 WHERE pod_uid = $1::uuid AND revoked_at IS NULL`, podUID, at)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// UnrevokedPods lists the namespace and UID of Pods that still hold
// unexpired, unrevoked certificates, for the reconciliation after a restart.
func (s Store) UnrevokedPods(ctx context.Context, now time.Time) ([]revoker.PodRef, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT DISTINCT namespace, pod_uid::text FROM identity.issued_certificates
		 WHERE pod_uid IS NOT NULL AND revoked_at IS NULL AND expires_at > $1
		 ORDER BY 1, 2`, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (revoker.PodRef, error) {
		var p revoker.PodRef
		err := row.Scan(&p.Namespace, &p.UID)
		return p, err
	})
}

// Registration is one initial registered_workloads row (install input).
type Registration struct {
	Namespace        string
	KSA              string
	Role             pki.Role
	AdapterID        string
	ServicePrincipal string
}

// UpsertRegistrations inserts or updates rows in one transaction. It never
// deletes rows that are not in the input and never re-enables a disabled row.
func (s Store) UpsertRegistrations(ctx context.Context, regs []Registration) (inserted, updated int, err error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)
	for _, r := range regs {
		var wasInsert bool
		err := tx.QueryRow(ctx,
			`INSERT INTO identity.registered_workloads (namespace, ksa, role, adapter_id, service_principal)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (namespace, ksa) DO UPDATE
			   SET role = EXCLUDED.role, adapter_id = EXCLUDED.adapter_id, service_principal = EXCLUDED.service_principal
			 RETURNING (xmax = 0)`,
			r.Namespace, r.KSA, string(r.Role), nullable(r.AdapterID), nullable(r.ServicePrincipal)).Scan(&wasInsert)
		if err != nil {
			return 0, 0, fmt.Errorf("%s/%s: %w", r.Namespace, r.KSA, err)
		}
		if wasInsert {
			inserted++
		} else {
			updated++
		}
	}
	return inserted, updated, tx.Commit(ctx)
}
