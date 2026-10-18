// Package results persists trusted TASK-10 correlation calculations. It is an
// internal storage adapter, not a public API or a source-authentication boundary.
package results

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/results/resultsdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrStaleRevision = errors.New("correlation calculation is based on a stale revision")

type Config struct{ SourceID, Version, Epoch, Tenant string }
type Store struct {
	Pool   *pgxpool.Pool
	Config Config
}

// Result uses the documented correlation columns. Method, reason and evidence
// references come from the trusted calculation adapter; this package does not
// invent wire enums or promote a caller's hint into confirmed attribution.
type Result struct {
	ID, KernelEventID                            uuid.UUID
	Revision                                     int32
	ActionID, AttemptID                          *uuid.UUID
	WorkloadID                                   *string
	Confidence, Method, AlgorithmVersion, Reason string
	EvidenceRefs                                 []string
	CandidateCount                               int32
	Limitations                                  []string
	CreatedAt                                    time.Time
}

// Append serializes per-kernel-event revision allocation and commits the derived
// row, audit event and audit outbox together. A retry of the current result is a
// no-op. Other stale calculations must reload/recompute instead of overwriting
// later evidence. expectedRevision is internal optimistic concurrency state, not
// an additional HTTP field. Callers must provide complete verified source data.
func (s Store) Append(ctx context.Context, in Result, expectedRevision int32) (Result, bool, error) {
	if s.Pool == nil || !validText(s.Config.SourceID) || !validText(s.Config.Version) || !validText(s.Config.Epoch) || !validText(s.Config.Tenant) {
		return Result{}, false, errors.New("database and audit source/version/epoch/tenant are required")
	}
	if expectedRevision < 0 || in.ID != uuid.Nil || in.Revision != 0 || !in.CreatedAt.IsZero() {
		return Result{}, false, errors.New("store allocates result ID, revision and creation time")
	}
	if err := validate(in); err != nil {
		return Result{}, false, err
	}
	in = normalize(in)
	var out Result
	created := false
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		q := resultsdb.New(tx)
		if err := q.LimitLockWait(ctx); err != nil {
			return err
		}
		if err := q.LockKernelResult(ctx, in.KernelEventID.String()); err != nil {
			return err
		}
		row, err := q.Latest(ctx, pgUUID(in.KernelEventID))
		var revision int32
		if err == nil {
			old, err := fromDB(row)
			if err != nil {
				return err
			}
			revision = old.Revision
			if equivalent(old, in) {
				out = old
				return nil
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if revision != expectedRevision {
			return ErrStaleRevision
		}
		if revision == math.MaxInt32 {
			return errors.New("correlation revision exhausted")
		}
		out = in
		out.ID = uuid.New()
		out.Revision = revision + 1
		out.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
		refs, err := json.Marshal(out.EvidenceRefs)
		if err != nil {
			return err
		}
		if err := q.Insert(ctx, resultsdb.InsertParams{
			ID: pgUUID(out.ID), KernelID: pgUUID(out.KernelEventID), Revision: out.Revision,
			ActionID: nullableUUID(out.ActionID), AttemptID: nullableUUID(out.AttemptID), WorkloadID: nullableText(out.WorkloadID),
			Confidence: out.Confidence, Method: out.Method, EvidenceRefs: refs, CandidateCount: out.CandidateCount,
			AlgorithmVersion: out.AlgorithmVersion, Reason: out.Reason, Limitations: out.Limitations,
			CreatedAt: pgtype.Timestamptz{Time: out.CreatedAt, Valid: true},
		}); err != nil {
			return err
		}
		event := map[string]any{
			"event_id": uuid.NewString(), "event_type": "kernel_correlation_checked", "tenant": s.Config.Tenant,
			"source_id": s.Config.SourceID, "source_version": s.Config.Version, "source_epoch": s.Config.Epoch,
			"source_sequence": nil, "source_time": out.CreatedAt.Format(time.RFC3339Nano), "schema_version": 1,
			"evidence_refs": out.EvidenceRefs,
			"safe_payload": map[string]any{"correlation_id": out.ID.String(), "kernel_event_id": out.KernelEventID.String(),
				"confidence": out.Confidence, "algorithm_version": out.AlgorithmVersion, "revision": out.Revision},
		}
		if out.WorkloadID != nil {
			event["workload_id"] = *out.WorkloadID
		}
		if out.ActionID != nil {
			event["action_id"] = out.ActionID.String()
		}
		if out.AttemptID != nil {
			event["attempt_id"] = out.AttemptID.String()
		}
		raw, err := json.Marshal(event)
		if err != nil {
			return err
		}
		digest, err := canonical.PayloadDigest(raw)
		if err != nil {
			return err
		}
		event["payload_digest"] = digest
		raw, err = json.Marshal(event)
		if err != nil {
			return err
		}
		result, err := q.AppendAudit(ctx, raw)
		if err != nil {
			return err
		}
		if result != "created" {
			return errors.New("correlation audit append did not create event")
		}
		created = true
		return nil
	})
	if err != nil {
		return Result{}, false, err
	}
	return out, created, nil
}

func (s Store) Latest(ctx context.Context, kernel uuid.UUID) (Result, error) {
	if s.Pool == nil || kernel == uuid.Nil {
		return Result{}, errors.New("database and kernel ID are required")
	}
	row, err := resultsdb.New(s.Pool).Latest(ctx, pgUUID(kernel))
	if err != nil {
		return Result{}, err
	}
	return fromDB(row)
}

func validText(s string) bool {
	return strings.TrimSpace(s) != "" && len(s) <= 16384 && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func validate(r Result) error {
	if r.KernelEventID == uuid.Nil || r.CandidateCount < 0 || !validText(r.Method) || !validText(r.AlgorithmVersion) || !validText(r.Reason) {
		return errors.New("invalid correlation identity or calculation metadata")
	}
	for _, id := range []*uuid.UUID{r.ActionID, r.AttemptID} {
		if id != nil && *id == uuid.Nil {
			return errors.New("invalid attribution ID")
		}
	}
	if r.WorkloadID != nil && !validText(*r.WorkloadID) {
		return errors.New("invalid workload identity")
	}
	switch r.Confidence {
	case "confirmed":
		if r.AttemptID == nil || r.ActionID == nil || r.WorkloadID == nil || r.CandidateCount != 1 {
			return errors.New("confirmed requires unique attempt/action and workload")
		}
	case "workload_inferred":
		if r.WorkloadID == nil || r.ActionID != nil || r.AttemptID != nil {
			return errors.New("workload inference cannot assign an action or attempt")
		}
	case "unlinked":
		if r.ActionID != nil || r.AttemptID != nil {
			return errors.New("unlinked result cannot assign an action or attempt")
		}
	default:
		return errors.New("invalid confidence")
	}
	for _, list := range [][]string{r.EvidenceRefs, r.Limitations} {
		if len(list) > 1000 {
			return errors.New("too many correlation references or limitations")
		}
		for _, v := range list {
			if !validText(v) {
				return errors.New("invalid correlation reference or limitation")
			}
		}
	}
	return nil
}
func normalize(r Result) Result {
	// References and limitations are sets of supporting facts, not ordered joins.
	r.EvidenceRefs = sortedSet(r.EvidenceRefs)
	r.Limitations = sortedSet(r.Limitations)
	if r.ActionID != nil {
		v := *r.ActionID
		r.ActionID = &v
	}
	if r.AttemptID != nil {
		v := *r.AttemptID
		r.AttemptID = &v
	}
	if r.WorkloadID != nil {
		v := *r.WorkloadID
		r.WorkloadID = &v
	}
	return r
}
func sortedSet(v []string) []string {
	out := append([]string{}, v...)
	slices.Sort(out)
	return slices.Compact(out)
}
func equivalent(a, b Result) bool {
	a.ID, b.ID = uuid.Nil, uuid.Nil
	a.Revision, b.Revision = 0, 0
	a.CreatedAt, b.CreatedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(normalize(a), normalize(b))
}
func pgUUID(v uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: v, Valid: true} }
func nullableUUID(v *uuid.UUID) pgtype.UUID {
	if v == nil {
		return pgtype.UUID{}
	}
	return pgUUID(*v)
}
func nullableText(v *string) pgtype.Text {
	if v == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *v, Valid: true}
}
func fromDB(row resultsdb.CorrelationCorrelation) (Result, error) {
	r := Result{ID: uuid.UUID(row.CorrelationID.Bytes), KernelEventID: uuid.UUID(row.KernelEventID.Bytes), Revision: row.Revision,
		Confidence: row.Confidence, Method: row.Method, CandidateCount: row.CandidateCount, AlgorithmVersion: row.AlgorithmVersion,
		Reason: row.Reason, Limitations: row.Limitations, CreatedAt: row.CreatedAt.Time.UTC()}
	if row.ActionID.Valid {
		v := uuid.UUID(row.ActionID.Bytes)
		r.ActionID = &v
	}
	if row.AttemptID.Valid {
		v := uuid.UUID(row.AttemptID.Bytes)
		r.AttemptID = &v
	}
	if row.WorkloadID.Valid {
		v := row.WorkloadID.String
		r.WorkloadID = &v
	}
	if err := json.Unmarshal(row.EvidenceRefs, &r.EvidenceRefs); err != nil {
		return Result{}, err
	}
	return r, nil
}
