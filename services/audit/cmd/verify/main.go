// Command verify checks an explicitly bounded manifest range against pinned
// public keys, exact GCS generations and fixed-batch PostgreSQL outbox acks.
// A definite failure is reported as an export_verification_failed AuditEvent
// through the audit writer and an audit_integrity hold (TASK-07 3.2.1).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	export "github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/export"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/healthreport"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	verifierSAN      = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-verifier"
	writerSAN        = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"
	controlHealthSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"
)

func run(ctx context.Context) error {
	bucket := flag.String("bucket", "", "evidence bucket for the selected chain")
	chain := flag.String("chain", "gcs", "gcs or gcs_decision_inputs")
	keysFile := flag.String("keys", "", "trusted JSON mapping of exact KMS key versions to PEM public keys")
	from := flag.Int64("from", 1, "first manifest sequence")
	through := flag.Int64("through", 0, "last manifest sequence, required")
	previous := flag.String("previous-digest", "", "optional operator-verified predecessor digest when from > 1; must match the committed DB row")
	writerURL := flag.String("writer-url", "", "audit writer HTTPS origin for incident events")
	healthURL := flag.String("health-url", "", "control-health HTTPS origin for audit_integrity holds")
	sourceID := flag.String("source-id", "", "registered audit-verifier source")
	version := flag.String("version", "", "deployed verifier version")
	cert := flag.String("tls-cert", "", "client certificate PEM path (file mode)")
	key := flag.String("tls-key", "", "client private key PEM path (file mode)")
	ca := flag.String("tls-ca", "", "trust bundle PEM path")
	identityURL := flag.String("identity-url", "", "identity HTTPS origin for in-memory certificate bootstrap")
	token := flag.String("bootstrap-token", "", "projected agentarium-identity token file")
	flag.Parse()
	if *bucket == "" || *keysFile == "" || (*chain != "gcs" && *chain != "gcs_decision_inputs") || *from < 1 || *through < *from || *through > export.MaxSequence || (*from == 1 && *previous != "") || os.Getenv("DATABASE_URL") == "" {
		return errors.New("required verification inputs missing or invalid")
	}
	// Incident delivery is mandatory: a verifier that cannot report must not run.
	if *writerURL == "" || *healthURL == "" || *sourceID == "" || *version == "" {
		return errors.New("incident reporting inputs (writer-url, health-url, source-id, version) required")
	}
	keys, err := export.LoadTrustedKeys(*keysFile)
	if err != nil {
		return err
	}
	identity, err := healthreport.LoadIdentity(ctx, *identityURL, *token, *ca, *cert, *key, verifierSAN)
	if err != nil {
		return errors.New("cannot load TLS material")
	}
	writerClient, err := identity.Client(*writerURL, writerSAN)
	if err != nil {
		return errors.New("invalid writer client configuration")
	}
	holdClient, err := identity.Client(*healthURL, controlHealthSAN)
	if err != nil {
		return errors.New("invalid control-health client configuration")
	}
	reporter := &export.IncidentReporter{WriterURL: *writerURL, HoldURL: *healthURL, Writer: writerClient, Holds: holdClient, SourceID: *sourceID, Version: *version}
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return errors.New("database configuration failed")
	}
	defer pool.Close()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return errors.New("GCS client initialization failed")
	}
	defer client.Close()
	objects := export.GCS{Bucket: client.Bucket(*bucket)}
	acks := export.PGAcks{Queries: auditdb.New(pool), Destination: *chain}
	// Daily anchors are out of MVP scope (TASK-07 3.2.1): a later start uses the
	// predecessor digest still committed in export_manifests within retention.
	var prev *string
	if *from > 1 {
		row, e := auditdb.New(pool).ManifestForSequence(ctx, auditdb.ManifestForSequenceParams{ChainID: *chain, ManifestSeq: *from - 1})
		if e != nil {
			return fmt.Errorf("predecessor manifest %d unavailable: %w", *from-1, e)
		}
		if *previous != "" && *previous != row.ManifestDigest {
			return errors.New("operator predecessor digest differs from committed manifest")
		}
		prev = &row.ManifestDigest
	}
	incident := func(sequence int64, verr error, objectKey string) error {
		code := export.FailureCode(verr)
		if code == "" {
			// Network, permission or DB errors leave verification incomplete;
			// they are not evidence of tampering and raise no security hold.
			return fmt.Errorf("manifest %d verification incomplete: %w", sequence, verr)
		}
		call, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		inc, err := reporter.Report(call, *chain, sequence, code, objectKey)
		if err != nil {
			return fmt.Errorf("manifest %d failed verification (%s): %v; incident reporting failed: %w", sequence, code, verr, err)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"chain": *chain, "verified": false, "incident": inc})
		return fmt.Errorf("manifest %d failed verification: %w", sequence, verr)
	}
	type result struct {
		Sequence int64  `json:"manifest_seq"`
		Result   string `json:"result"`
	}
	results := []result{}
	skipped := 0
	q := auditdb.New(pool)
	for sequence := *from; sequence <= *through; sequence++ {
		objectKey := "manifests/" + strconv.FormatInt(sequence, 10) + ".json"
		// Both timestamps are DB-assigned and immutable (migration
		// 20261018091801). The window uses the intent time, which is also the
		// signed manifest created_at; retention purges rows only 31 days after
		// the later manifest commit (TASK-07 3.2.1).
		row, e := q.ManifestTimes(ctx, auditdb.ManifestTimesParams{ChainID: *chain, ManifestSeq: sequence})
		haveRow := e == nil
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return fmt.Errorf("manifest %d commit time unavailable: %w", sequence, e)
		}
		outside := haveRow && row.Outside
		skip := func() {
			results = append(results, result{sequence, "skipped_outside_window"})
			skipped++
			prev = &row.ManifestDigest // committed DB digest keeps the chain
		}
		attrs, e := objects.Bucket.Object(objectKey).Attrs(ctx)
		if errors.Is(e, storage.ErrObjectNotExist) {
			if outside {
				skip()
				continue
			}
			return incident(sequence, &export.VerificationError{Code: export.FailManifestMissing, Err: errors.New("manifest missing")}, objectKey)
		}
		if e != nil {
			return fmt.Errorf("manifest %d unreadable: %w", sequence, e)
		}
		if attrs.Size > export.MaxManifestBytes {
			return incident(sequence, &export.VerificationError{Code: export.FailManifestInvalid, Err: errors.New("manifest too large")}, objectKey)
		}
		raw, e := objects.Read(ctx, objectKey, attrs.Generation)
		if e != nil {
			return fmt.Errorf("manifest %d generation unreadable: %w", sequence, e)
		}
		batchKey := objectKey
		env, decodeErr := export.Decode(raw)
		if decodeErr == nil {
			batchKey = env.Manifest.ObjectKey
		}
		// The signed time must equal the DB intent time: a mismatch means one of
		// them was altered, which would also move the window.
		if haveRow && decodeErr == nil {
			signed, te := time.Parse(time.RFC3339Nano, env.Manifest.CreatedAt)
			if te != nil || !row.IntentAt.Valid || !signed.Equal(row.IntentAt.Time) {
				return incident(sequence, &export.VerificationError{Code: export.FailManifestInvalid, Err: errors.New("signed created_at differs from the DB intent time")}, batchKey)
			}
		}
		var digest string
		if outside {
			digest, e = export.VerifyDetached(ctx, raw, sequence, prev, keys, objects)
			if export.FailureCode(e) == export.FailObjectMissing {
				skip() // batch object expired with its bucket lifecycle
				continue
			}
		} else {
			digest, e = export.Verify(ctx, raw, sequence, prev, keys, objects, acks)
		}
		if e != nil {
			return incident(sequence, e, batchKey)
		}
		if haveRow && row.ManifestDigest != digest {
			return incident(sequence, &export.VerificationError{Code: export.FailManifestInvalid, Err: errors.New("committed DB manifest digest differs from the stored manifest")}, batchKey)
		}
		if outside {
			results = append(results, result{sequence, "verified_outside_window"})
		} else {
			results = append(results, result{sequence, "verified"})
		}
		prev = &digest
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"chain": *chain, "from": *from, "through": *through, "last_manifest_digest": *prev,
		"verified": skipped == 0, "results": results, "skipped_outside_window": skipped}); err != nil {
		return err
	}
	if skipped > 0 {
		return errIncomplete
	}
	return nil
}

// errIncomplete exits 2: no integrity failure, but some manifests outside the
// window could not be checked because their objects expired.
var errIncomplete = errors.New("some manifests outside the verification window were skipped")

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, errIncomplete) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
