package export

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrManifestObjectMissing = errors.New("manifest object not found")
var ErrManifestChainBusy = errors.New("manifest chain busy or predecessor intent unfinished")
var ErrLeaderLeaseMissing = errors.New("manifest leader lease is not wired")

// LeaderLease returns the fencing token of a renewed, time-bounded lease the
// caller still owns for this chain. PGLease is the production implementation
// (TASK-07 3.2.1). The DB trigger rejects intents and manifests carrying a
// stale token; the advisory lock below is only an extra serialization guard.
type LeaderLease interface {
	Check(context.Context, string) (int64, error)
}

type ManifestObjects interface {
	CreateFixed(context.Context, string, string, []byte) (int64, error)
	ReadManifest(context.Context, string) ([]byte, error)
}

// ManifestPublisher composes DB intents, immutable GCS objects and KMS signing.
// It fails closed without a leader lease and uses one fencing token for the
// whole publication; a token change aborts and the batch is retried.
type ManifestPublisher struct {
	// Chain binds this publisher and its bucket adapter to one destination.
	// Empty preserves the existing gcs default.
	Chain      string
	Pool       *pgxpool.Pool
	Objects    ManifestObjects
	Signer     Signer
	KeyVersion string
	Keys       map[string]*ecdsa.PublicKey
	Leader     LeaderLease
}

// Ready prevents the worker from claiming rows without required configuration
// and current leader authorization. Publication repeats ownership checks.
func (p ManifestPublisher) Ready(ctx context.Context, chain string) error {
	if p.Leader == nil {
		return ErrLeaderLeaseMissing
	}
	key := p.Keys[p.KeyVersion]
	if (chain != "gcs" && chain != "gcs_decision_inputs") || chain != p.chain() || p.Pool == nil || p.Objects == nil || p.Signer == nil || key == nil || key.Curve != elliptic.P256() {
		return errors.New("invalid manifest publisher configuration")
	}
	_, err := p.Leader.Check(ctx, chain)
	return err
}

// still verifies that the lease captured at the start is still held.
func (p ManifestPublisher) still(ctx context.Context, chain string, token int64) error {
	current, err := p.Leader.Check(ctx, chain)
	if err != nil {
		return err
	}
	if current != token {
		return ErrLeaseLost
	}
	return nil
}

func (p ManifestPublisher) Publish(ctx context.Context, c *Claim, data []byte, sources []Source) (Receipt, error) {
	if p.Leader == nil {
		return Receipt{}, ErrLeaderLeaseMissing
	}
	if c == nil || !validClass(c.SourceClass) || c.Destination != destinationForClass(c.SourceClass) {
		return Receipt{}, errors.New("invalid manifest claim destination")
	}
	if err := p.Ready(ctx, c.Destination); err != nil {
		return Receipt{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	token, err := p.Leader.Check(ctx, c.Destination)
	if err != nil {
		return Receipt{}, err
	}
	// Read back fixed immutable rows: callers cannot publish another body's
	// digest or a different source range under this batch identity.
	expected, expectedSources, err := (Outbox{Pool: p.Pool}).Records(ctx, c)
	if err != nil {
		return Receipt{}, err
	}
	a, err := canonicalJSON(sources)
	if err != nil {
		return Receipt{}, err
	}
	b, err := canonicalJSON(expectedSources)
	if err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(data, expected) || !bytes.Equal(a, b) {
		return Receipt{}, errors.New("publisher input differs from fixed records")
	}
	generation, err := p.Objects.CreateFixed(ctx, c.ObjectKey, "application/x-ndjson", data)
	if err != nil {
		return Receipt{}, err
	}
	conn, err := p.Pool.Acquire(ctx)
	if err != nil {
		return Receipt{}, err
	}
	q := auditdb.New(conn)
	chainKey := int32(1)
	if c.Destination == "gcs_decision_inputs" {
		chainKey = 2
	}
	locked, err := q.TryManifestChainLock(ctx, chainKey)
	if err != nil || !locked {
		conn.Release()
		if err != nil {
			return Receipt{}, err
		}
		return Receipt{}, ErrManifestChainBusy
	}
	defer func() {
		releaseCtx, done := context.WithTimeout(context.Background(), 2*time.Second)
		defer done()
		released, e := q.ReleaseManifestChainLock(releaseCtx, chainKey)
		if e != nil || !released {
			raw := conn.Hijack()
			_ = raw.Close(releaseCtx)
		} else {
			conn.Release()
		}
	}()
	if err = p.still(ctx, c.Destination, token); err != nil {
		return Receipt{}, err
	}
	intent, err := p.intent(ctx, conn, c, token)
	if err != nil {
		return Receipt{}, err
	}
	var previous *string
	if intent.ManifestSeq > 1 {
		prev, e := q.ManifestForSequence(ctx, auditdb.ManifestForSequenceParams{ChainID: c.Destination, ManifestSeq: intent.ManifestSeq - 1})
		if e != nil {
			return Receipt{}, fmt.Errorf("manifest predecessor: %w", e)
		}
		previous = &prev.ManifestDigest
	}
	m := Manifest{Sequence: intent.ManifestSeq, BatchID: c.BatchID, ObjectKey: c.ObjectKey, Generation: generation, BatchDigest: Digest(data), RecordCount: c.Count(), OutboxRange: c.OutboxRange(), Sources: sources, Previous: previous, CreatedAt: intent.CreatedAt.Time.UTC().Format(time.RFC3339Nano)}
	if err = m.Validate(); err != nil {
		return Receipt{}, err
	}
	objectKey := "manifests/" + strconv.FormatInt(m.Sequence, 10) + ".json"
	raw, err := p.Objects.ReadManifest(ctx, objectKey)
	if errors.Is(err, ErrManifestObjectMissing) {
		// A committed envelope disappearing is missing evidence, not a new
		// publication attempt. Do not replace it with a fresh signature.
		_, committedErr := q.ManifestForSequence(ctx, auditdb.ManifestForSequenceParams{ChainID: c.Destination, ManifestSeq: m.Sequence})
		if committedErr == nil {
			return Receipt{}, ErrManifestObjectMissing
		}
		if !errors.Is(committedErr, pgx.ErrNoRows) {
			return Receipt{}, committedErr
		}
		raw, err = Sign(ctx, m, p.KeyVersion, p.Signer)
		if err != nil {
			return Receipt{}, err
		}
		// Validate even injected signers before bytes become externally durable.
		if _, _, err = p.checkEnvelope(raw, m); err != nil {
			return Receipt{}, err
		}
		if err = p.still(ctx, c.Destination, token); err != nil {
			return Receipt{}, err
		}
		_, err = p.Objects.CreateFixed(ctx, objectKey, "application/json", raw)
		if errors.Is(err, ErrObjectConflict) {
			raw, err = p.Objects.ReadManifest(ctx, objectKey)
		}
	}
	if err != nil {
		return Receipt{}, err
	}
	env, digest, err := p.checkEnvelope(raw, m)
	if err != nil {
		return Receipt{}, err
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if err != nil {
		return Receipt{}, err
	}
	if err = p.still(ctx, c.Destination, token); err != nil {
		return Receipt{}, err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback(ctx)
	tq := auditdb.New(tx)
	prev := pgtype.Text{}
	if previous != nil {
		prev = textValue(*previous)
	}
	err = tq.CommitExportManifest(ctx, auditdb.CommitExportManifestParams{ChainID: c.Destination, ManifestSeq: m.Sequence, ObjectGeneration: generation, BatchDigest: m.BatchDigest, PrevManifestDigest: prev, ManifestDigest: digest, KmsKeyVersion: env.KeyVersion, Signature: sig, ManifestObjectKey: objectKey, FencingToken: pgtype.Int8{Int64: token, Valid: true}})
	if fencingRejected(err) {
		return Receipt{}, ErrLeaseLost
	}
	if err != nil {
		return Receipt{}, err
	}
	stored, err := tq.ManifestForSequence(ctx, auditdb.ManifestForSequenceParams{ChainID: c.Destination, ManifestSeq: m.Sequence})
	if err != nil {
		return Receipt{}, err
	}
	if stored.ObjectGeneration != generation || stored.BatchDigest != m.BatchDigest || stored.ManifestDigest != digest || stored.KmsKeyVersion != env.KeyVersion || !bytes.Equal(stored.Signature, sig) || stored.ManifestObjectKey != objectKey || stored.PrevManifestDigest != prev {
		return Receipt{}, errors.New("committed manifest differs from immutable envelope")
	}
	if err = p.still(ctx, c.Destination, token); err != nil {
		return Receipt{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Receipt{}, err
	}
	return Receipt{Generation: generation, BatchDigest: m.BatchDigest, ManifestDigest: digest}, nil
}

func (p ManifestPublisher) intent(ctx context.Context, conn *pgxpool.Conn, c *Claim, token int64) (auditdb.AuditManifestIntent, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return auditdb.AuditManifestIntent{}, err
	}
	defer tx.Rollback(ctx)
	q := auditdb.New(tx)
	intent, err := q.IntentForBatch(ctx, batchUUID(c.BatchID))
	if errors.Is(err, pgx.ErrNoRows) {
		seq := int64(1)
		last, e := q.LatestIntent(ctx, c.Destination)
		if e == nil {
			if _, e = q.ManifestForSequence(ctx, auditdb.ManifestForSequenceParams{ChainID: c.Destination, ManifestSeq: last.ManifestSeq}); errors.Is(e, pgx.ErrNoRows) {
				return intent, ErrManifestChainBusy
			} else if e != nil {
				return intent, e
			}
			seq = last.ManifestSeq + 1
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return intent, e
		}
		if seq > MaxSequence {
			return intent, errors.New("manifest sequence exhausted")
		}
		intent, err = q.ReserveManifestIntent(ctx, auditdb.ReserveManifestIntentParams{ChainID: c.Destination, ManifestSeq: seq, BatchID: batchUUID(c.BatchID), FencingToken: pgtype.Int8{Int64: token, Valid: true}})
		if fencingRejected(err) {
			return intent, ErrLeaseLost
		}
	}
	if err != nil {
		return intent, err
	}
	if intent.ChainID != c.Destination {
		return intent, errors.New("intent belongs to another chain")
	}
	if err = p.still(ctx, c.Destination, token); err != nil {
		return intent, err
	}
	if err = tx.Commit(ctx); err != nil {
		return intent, err
	}
	return intent, nil
}
func (p ManifestPublisher) checkEnvelope(raw []byte, want Manifest) (Envelope, string, error) {
	env, err := Decode(raw)
	if err != nil {
		return env, "", err
	}
	got, err := canonicalJSON(env.Manifest)
	if err != nil {
		return env, "", err
	}
	expected, err := canonicalJSON(want)
	if err != nil {
		return env, "", err
	}
	if !bytes.Equal(got, expected) {
		return env, "", errors.New("existing manifest does not match fixed intent and object")
	}
	key := p.Keys[env.KeyVersion]
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signature)
	digest := sha256.Sum256(got)
	if err != nil || key == nil || key.Curve != elliptic.P256() || !ecdsa.VerifyASN1(key, digest[:], sig) {
		return env, "", errors.New("untrusted or invalid manifest signature")
	}
	return env, Digest(got), nil
}

func (p ManifestPublisher) chain() string {
	if p.Chain == "" {
		return "gcs"
	}
	return p.Chain
}
