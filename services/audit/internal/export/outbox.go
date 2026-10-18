package export

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrClaimLost = errors.New("export batch claim expired, changed, or partly locked")
var ErrManifestMissing = errors.New("matching committed manifest required before outbox acknowledgement")
var ErrUnsupportedRecord = errors.New("export record format or source range is not implemented")

// Claim is a process-local capability, fenced by every member's monotonic
// attempts value. It is not an HTTP or persisted wire contract.
type Claim struct {
	BatchID, Destination, SourceClass, ObjectKey string
	CreatedAt                                    time.Time
	members                                      []auditdb.LockBatchMembersRow
}

func (c *Claim) Count() int { return len(c.members) }

// OutboxRange is the exact min/max outbox_id of the fixed members.
func (c *Claim) OutboxRange() OutboxRange {
	if len(c.members) == 0 {
		return OutboxRange{}
	}
	r := OutboxRange{First: c.members[0].OutboxID, Last: c.members[0].OutboxID}
	for _, m := range c.members {
		r.First, r.Last = min(r.First, m.OutboxID), max(r.Last, m.OutboxID)
	}
	return r
}

type Outbox struct{ Pool *pgxpool.Pool }

func textValue(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }
func batchUUID(s string) pgtype.UUID {
	id, _ := uuid.Parse(s)
	return pgtype.UUID{Bytes: id, Valid: true}
}

// Claim fixes at most 100 members before any external I/O. Retried batches
// are locked all-or-none; a partly locked batch releases all acquired locks.
func (o Outbox) Claim(ctx context.Context, destination, class string) (*Claim, error) {
	if o.Pool == nil || !validClass(class) || (destination != "gcs" && destination != "gcs_decision_inputs") || (class == "decision_input") != (destination == "gcs_decision_inputs") {
		return nil, errors.New("invalid outbox configuration")
	}
	candidates, err := auditdb.New(o.Pool).RetryBatchCandidates(ctx, auditdb.RetryBatchCandidatesParams{Destination: destination, SourceClass: class})
	if err != nil {
		return nil, err
	}
	for _, id := range candidates {
		c, err := o.claimExisting(ctx, id)
		if err != nil {
			return nil, err
		}
		if c != nil {
			return c, nil
		}
	}
	tx, err := o.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := auditdb.New(tx)
	rows, err := q.LockUnbatched(ctx, auditdb.LockUnbatchedParams{Destination: destination, SourceClass: class})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	now, err := q.ExportDBTime(ctx)
	if err != nil {
		return nil, err
	}
	c := &Claim{BatchID: uuid.NewString(), Destination: destination, SourceClass: class, CreatedAt: now.Time}
	c.ObjectKey, err = ObjectKey(c.BatchID, class, c.CreatedAt)
	if err != nil {
		return nil, err
	}
	err = q.CreateExportBatch(ctx, auditdb.CreateExportBatchParams{BatchID: batchUUID(c.BatchID), Destination: textValue(destination), SourceClass: textValue(class), ObjectKey: textValue(c.ObjectKey), CreatedAt: now})
	if err != nil {
		return nil, err
	}
	for i, r := range rows {
		err = q.AddExportMember(ctx, auditdb.AddExportMemberParams{BatchID: batchUUID(c.BatchID), Ordinal: pgtype.Int4{Int32: int32(i + 1), Valid: true}, RecordKind: textValue(r.RecordKind), RecordID: textValue(r.RecordID), Destination: textValue(r.Destination)})
		if err != nil {
			return nil, err
		}
		c.members = append(c.members, auditdb.LockBatchMembersRow(r))
	}
	if err = claimMembers(ctx, q, c); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return c, nil
}
func (o Outbox) claimExisting(ctx context.Context, id pgtype.UUID) (*Claim, error) {
	tx, err := o.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := auditdb.New(tx)
	n, err := q.BatchMemberCount(ctx, id)
	if err != nil {
		return nil, err
	}
	rows, err := q.LockBatchMembers(ctx, id)
	if err != nil {
		return nil, err
	}
	if n < 1 || n > 100 || len(rows) != int(n) {
		return nil, nil
	}
	for _, r := range rows {
		if !r.Claimable {
			return nil, nil
		}
	}
	b, err := q.BatchInfo(ctx, id)
	if err != nil {
		return nil, err
	}
	c := &Claim{BatchID: uuid.UUID(id.Bytes).String(), Destination: b.Destination.String, SourceClass: b.SourceClass.String, ObjectKey: b.ObjectKey.String, CreatedAt: b.CreatedAt.Time, members: rows}
	if err = claimMembers(ctx, q, c); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return c, nil
}
func claimMembers(ctx context.Context, q *auditdb.Queries, c *Claim) error {
	for i, r := range c.members {
		attempt, err := q.ClaimOutboxMember(ctx, auditdb.ClaimOutboxMemberParams{RecordKind: r.RecordKind, RecordID: r.RecordID, Destination: r.Destination})
		if err != nil {
			return err
		}
		c.members[i].Attempts = attempt
	}
	return nil
}

// Receipt identifies the immutable data object and committed signed manifest.
// It is returned only by the manifest publisher after its own durable commit.
type Receipt struct {
	Generation                  int64
	BatchDigest, ManifestDigest string
}

func (o Outbox) Ack(ctx context.Context, c *Claim, r Receipt) error {
	if r.Generation < 1 || r.Generation > MaxSequence || !digestPattern.MatchString(r.BatchDigest) || !digestPattern.MatchString(r.ManifestDigest) {
		return errors.New("invalid export receipt")
	}
	return o.withClaim(ctx, c, func(q *auditdb.Queries) error {
		ok, err := q.CommittedExportManifest(ctx, auditdb.CommittedExportManifestParams{BatchID: batchUUID(c.BatchID), Destination: c.Destination, Generation: r.Generation, BatchDigest: r.BatchDigest, ManifestDigest: r.ManifestDigest})
		if err != nil {
			return err
		}
		if !ok {
			return ErrManifestMissing
		}
		ref := c.ObjectKey + "#" + strconv.FormatInt(r.Generation, 10)
		for _, m := range c.members {
			n, err := q.AckOutboxMember(ctx, auditdb.AckOutboxMemberParams{AckRef: ref, RecordKind: m.RecordKind, RecordID: m.RecordID, Destination: m.Destination, Attempts: m.Attempts})
			if err != nil {
				return err
			}
			if n != 1 {
				return ErrClaimLost
			}
		}
		return nil
	})
}
func retrySeconds(attempt int32) int32 {
	if attempt <= 1 {
		return 1
	}
	if attempt >= 6 {
		return 30
	}
	return 1 << uint(attempt-1)
}
func (o Outbox) Retry(ctx context.Context, c *Claim) error {
	return o.withClaim(ctx, c, func(q *auditdb.Queries) error {
		for _, m := range c.members {
			n, err := q.RetryOutboxMember(ctx, auditdb.RetryOutboxMemberParams{DelaySeconds: retrySeconds(m.Attempts), RecordKind: m.RecordKind, RecordID: m.RecordID, Destination: m.Destination, Attempts: m.Attempts})
			if err != nil {
				return err
			}
			if n != 1 {
				return ErrClaimLost
			}
		}
		return nil
	})
}
func (o Outbox) withClaim(ctx context.Context, c *Claim, fn func(*auditdb.Queries) error) error {
	if o.Pool == nil || c == nil || !validUUID(c.BatchID) || len(c.members) < 1 || len(c.members) > 100 {
		return ErrClaimLost
	}
	tx, err := o.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := auditdb.New(tx)
	b, err := q.BatchInfo(ctx, batchUUID(c.BatchID))
	if err != nil {
		return err
	}
	if b.Destination.String != c.Destination || b.ObjectKey.String != c.ObjectKey || b.SourceClass.String != c.SourceClass {
		return ErrClaimLost
	}
	rows, err := q.LockBatchMembers(ctx, batchUUID(c.BatchID))
	if err != nil {
		return err
	}
	n, err := q.BatchMemberCount(ctx, batchUUID(c.BatchID))
	if err != nil {
		return err
	}
	if len(rows) != len(c.members) || n != int64(len(c.members)) {
		return ErrClaimLost
	}
	for i, r := range rows {
		m := c.members[i]
		if r.RecordKind != m.RecordKind || r.RecordID != m.RecordID || r.Destination != m.Destination || r.Attempts != m.Attempts || r.State != "claimed" || !r.LeaseLive {
			return ErrClaimLost
		}
	}
	if err = fn(q); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Records preserves fixed ordinal order and reads the immutable stored rows.
// Unsequenced business records and decision inputs contribute no source range;
// the manifest outbox_range covers every member (TASK-07 3.2.1).
func (o Outbox) Records(ctx context.Context, c *Claim) ([]byte, []Source, error) {
	if c == nil || !validClass(c.SourceClass) || c.Destination != destinationForClass(c.SourceClass) {
		return nil, nil, ErrUnsupportedRecord
	}
	q := auditdb.New(o.Pool)
	fixed, err := q.BatchInfo(ctx, batchUUID(c.BatchID))
	if err != nil {
		return nil, nil, err
	}
	if fixed.Destination.String != c.Destination || fixed.SourceClass.String != c.SourceClass || fixed.ObjectKey.String != c.ObjectKey || !fixed.CreatedAt.Time.Equal(c.CreatedAt) {
		return nil, nil, ErrUnsupportedRecord
	}
	if c.SourceClass == "decision_input" {
		rows := make([]json.RawMessage, 0, len(c.members))
		for _, m := range c.members {
			if m.RecordKind != "decision_input" || m.Destination != c.Destination || !digestPattern.MatchString(m.RecordID) {
				return nil, nil, ErrUnsupportedRecord
			}
			row, err := q.ExportDecisionInput(ctx, m.RecordID)
			if err != nil {
				return nil, nil, err
			}
			rows = append(rows, row)
		}
		data, err := DecisionNDJSON(rows)
		return data, []Source{}, err
	}
	records := make([]Record, 0, len(c.members))
	expectedKind := map[string]string{"business": "audit_event", "kernel": "kernel_event", "lifecycle": "lifecycle_event"}[c.SourceClass]
	for _, m := range c.members {
		if m.RecordKind != expectedKind || !validUUID(m.RecordID) {
			return nil, nil, ErrUnsupportedRecord
		}
		var record []byte
		var eventType string
		var err error
		switch m.RecordKind {
		case "audit_event":
			var row auditdb.ExportAuditRecordRow
			row, err = q.ExportAuditRecord(ctx, batchUUID(m.RecordID))
			record, eventType = row.Record, row.EventType
		case "kernel_event":
			record, err = q.ExportKernelRecord(ctx, batchUUID(m.RecordID))
			eventType = "kernel_event_observed"
		case "lifecycle_event":
			record, err = q.ExportLifecycleRecord(ctx, batchUUID(m.RecordID))
			eventType = "lifecycle_recorded"
		}
		if err != nil {
			return nil, nil, err
		}
		records = append(records, Record{Kind: m.RecordKind, EventType: eventType, Body: record})
	}
	sources, err := recordSources(records)
	if err != nil {
		return nil, nil, err
	}
	data, err := NDJSON(records)
	return data, sources, err
}

// Publisher performs create-only upload and durable manifest publication. It
// must preserve/reconcile signing bytes and serialize the chain. Until the
// leader/intent recovery adapter exists, Worker refuses to claim anything.
type Publisher interface {
	Ready(context.Context, string) error
	Publish(context.Context, *Claim, []byte, []Source) (Receipt, error)
}
type Worker struct {
	Outbox    Outbox
	Publisher Publisher
	// SourceClass selects an evidence class; empty preserves business defaults.
	SourceClass string
}

func (w Worker) Once(ctx context.Context) (bool, error) {
	if w.Publisher == nil {
		return false, errors.New("manifest publisher not wired")
	}
	class := w.SourceClass
	if class == "" {
		class = "business"
	}
	if !validClass(class) {
		return false, ErrUnsupportedRecord
	}
	destination := destinationForClass(class)
	if err := w.Publisher.Ready(ctx, destination); err != nil {
		return false, err
	}
	c, err := w.Outbox.Claim(ctx, destination, class)
	if err != nil || c == nil {
		return false, err
	}
	data, sources, err := w.Outbox.Records(ctx, c)
	if err == nil {
		var r Receipt
		r, err = w.Publisher.Publish(ctx, c, data, sources)
		if err == nil {
			if r.BatchDigest != Digest(data) {
				err = errors.New("publisher receipt has wrong batch digest")
			} else {
				err = w.Outbox.Ack(ctx, c, r)
			}
		}
	}
	if err != nil {
		if retryErr := w.Outbox.Retry(ctx, c); retryErr != nil {
			return true, fmt.Errorf("export failed: %w; retry: %v", err, retryErr)
		}
		return true, err
	}
	return true, nil
}

func destinationForClass(class string) string {
	if class == "decision_input" {
		return "gcs_decision_inputs"
	}
	return "gcs"
}
