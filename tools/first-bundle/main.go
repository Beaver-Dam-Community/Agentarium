// Command first-bundle builds, signs and (with -publish) publishes the first
// policy bundle and points desired_bundle at it (M2-6a, TASK-14 3.2).
//
// It is a one-off bootstrap tool, not the releaser: it does not create holds,
// wait for lease acks or touch active_policy. Later bundles go through the
// releaser's activation flow (the rest of TASK-14).
//
// Order, so a failure never leaves desired_bundle pointing at a bad object:
//
//  1. build the bundle and compute candidate_digest
//  2. with -publish, read the environment's desired_bundle row; if there is
//     one, reuse it (below) and stop without signing or uploading
//  3. sign with Cloud KMS (EC_SIGN_P256_SHA256) and compute artifact_digest
//  4. verify the signed tarball with OPA using the KMS public key
//  5. upload gs://<bucket>/bundles/<artifact_digest>.tar.gz only if absent;
//     if present, read it back and require the same SHA-256
//  6. insert the desired_bundle row; an existing row is never replaced. If
//     another run inserted first, its row is checked as in 2.
//
// KMS ECDSA signatures are randomized, so signing the same bundle twice gives
// a different artifact_digest. A retry is recognized by candidate_digest
// instead: the existing row is reused only if its object_uri names the
// -bucket and its artifact_digest, the object has that SHA-256, it verifies
// with the -kms-key-version public key under -key-id, its revision is
// -revision, its candidate_digest is the one built in 1, and bundle_id,
// environment and set_by_change_id are the flags. Then the result describes
// the existing row and object (-out gets the existing bytes). Anything else
// is an error; first-bundle never rewrites the row or the object.
//
// A failure after 5 leaves an unreferenced, content-addressed object, which
// is harmless. Losing the insert race in 6 does the same: both runs upload
// and the loser's object stays unreferenced.
package main

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5"
	"google.golang.org/api/googleapi"

	"github.com/Beaver-Dam-Community/Agentarium/packages/bundles"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

type result struct {
	BundleID        string `json:"bundle_id"`
	Revision        string `json:"revision"`
	CandidateDigest string `json:"candidate_digest"`
	ArtifactDigest  string `json:"artifact_digest"`
	KeyID           string `json:"key_id"`
	ObjectURI       string `json:"object_uri,omitempty"`
	Environment     string `json:"environment,omitempty"`
	Published       bool   `json:"published"`
}

// maxObjectBytes bounds what is read back from the bucket (the bundles
// package reads at most 64 MiB of a tarball).
const maxObjectBytes = 64 << 20

var (
	// changeIDPattern is a canonical lower-case UUID, the form PostgreSQL
	// prints, so the value read back compares equal to the flag.
	changeIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func main() {
	var (
		policyDir   = flag.String("policy-dir", "", "directory of Rego modules (required)")
		catalogDir  = flag.String("catalog-dir", "catalog/gcp", "catalog directory (operations.yaml, targets.yaml)")
		policyData  = flag.String("policy-data", "", "policy data JSON file (required)")
		revision    = flag.String("revision", "", ".manifest revision (required)")
		bundleID    = flag.String("bundle-id", "", "bundle_id (required)")
		keyVersion  = flag.String("kms-key-version", "", "projects/.../cryptoKeyVersions/N (required)")
		keyID       = flag.String("key-id", "prod-v1", "OPA keyID: prod-v1 or regression-v1")
		out         = flag.String("out", "", "also write the signed tarball to this file")
		publish     = flag.Bool("publish", false, "upload to GCS and set desired_bundle")
		bucket      = flag.String("bucket", "", "bundle bucket (with -publish)")
		environment = flag.String("environment", "", "desired_bundle.environment (with -publish)")
		changeID    = flag.String("set-by-change-id", "", "desired_bundle.set_by_change_id, a lower-case UUID (with -publish)")
	)
	flag.Parse()
	if *policyDir == "" || *policyData == "" || *revision == "" || *bundleID == "" || *keyVersion == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *keyID != "prod-v1" && *keyID != "regression-v1" {
		log.Fatalf("-key-id must be prod-v1 or regression-v1")
	}
	if *publish && (*bucket == "" || *environment == "" || *changeID == "" || os.Getenv("DATABASE_URL") == "") {
		log.Fatalf("-publish needs -bucket, -environment, -set-by-change-id and DATABASE_URL")
	}
	if *publish {
		if err := checkChangeID(*changeID); err != nil {
			log.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	u, err := buildBundle(*policyDir, *catalogDir, *policyData, *revision, *publish)
	if err != nil {
		log.Fatal(err)
	}
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer kmsClient.Close()
	key, err := bundles.NewKMSSigner(ctx, kmsClient, *keyVersion)
	if err != nil {
		log.Fatal(err)
	}

	var (
		res     result
		tarball []byte
	)
	if *publish {
		gcs, err := storage.NewClient(ctx)
		if err != nil {
			log.Fatal(err)
		}
		defer gcs.Close()
		conn, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close(ctx)
		p := publisher{key: key, store: gcsStore{gcs}, db: conn}
		res, tarball, err = p.publish(ctx, u, publishParams{
			BundleID: *bundleID, Revision: *revision, KeyID: *keyID,
			Bucket: *bucket, Environment: *environment, ChangeID: *changeID,
		})
		if err != nil {
			log.Fatal(err)
		}
	} else {
		s, err := signAndVerify(u, key, *keyID, *revision)
		if err != nil {
			log.Fatal(err)
		}
		res = result{
			BundleID: *bundleID, Revision: *revision, KeyID: *keyID,
			CandidateDigest: s.CandidateDigest, ArtifactDigest: s.ArtifactDigest,
		}
		tarball = s.Tarball
	}
	if *out != "" {
		if err := os.WriteFile(*out, tarball, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}

func checkChangeID(id string) error {
	if !changeIDPattern.MatchString(id) {
		return fmt.Errorf("-set-by-change-id %q is not a canonical lower-case UUID", id)
	}
	return nil
}

func buildBundle(policyDir, catalogDir, policyDataPath, revision string, publish bool) (*bundles.Unsigned, error) {
	cat, err := canonical.LoadCatalogDir(catalogDir)
	if err != nil {
		return nil, err
	}
	pd, err := os.ReadFile(policyDataPath)
	if err != nil {
		return nil, err
	}
	u, err := bundles.Build(bundles.Input{PolicyDir: policyDir, Catalog: cat, PolicyData: pd, Revision: revision})
	if err != nil {
		return nil, err
	}
	// The gateway prepares data.agentarium.gateway.result (TASK-04 3.1). A
	// bundle without it cannot serve, so it must not become desired_bundle.
	if publish && !u.DefinesRule("agentarium.gateway", "result") {
		return nil, errors.New("policy dir has no agentarium.gateway result rule; refusing to publish")
	}
	return u, nil
}

// keyVersion is the signing key: bundles.KMSSigner in the CLI, a local
// ECDSA key in tests. PublicKeyPEM must not call Sign.
type keyVersion interface {
	crypto.Signer
	PublicKeyPEM() string
}

func signAndVerify(u *bundles.Unsigned, key keyVersion, keyID, revision string) (*bundles.Signed, error) {
	s, err := bundles.Sign(u, key, keyID)
	if err != nil {
		return nil, err
	}
	rev, err := bundles.Verify(s.Tarball, key.PublicKeyPEM(), keyID)
	if err != nil {
		return nil, err
	}
	if rev != revision {
		return nil, fmt.Errorf("verified revision %q, want %q", rev, revision)
	}
	return s, nil
}

// objectStore is the bundle bucket: GCS in the CLI, in memory in tests.
type objectStore interface {
	// createIfAbsent writes the object only if it does not exist. existed
	// reports that it did, and nothing was written.
	createIfAbsent(ctx context.Context, bucket, name string, body []byte) (existed bool, err error)
	// read returns the object, at most maxObjectBytes.
	read(ctx context.Context, bucket, name string) ([]byte, error)
}

func objectName(artifactDigest string) string { return "bundles/" + artifactDigest + ".tar.gz" }

func objectURI(bucket, artifactDigest string) string {
	return "gs://" + bucket + "/" + objectName(artifactDigest)
}

type publishParams struct {
	BundleID, Revision, KeyID     string
	Bucket, Environment, ChangeID string
}

type publisher struct {
	key   keyVersion
	store objectStore
	db    *pgx.Conn
}

// publish runs steps 2–6 of the package comment for an unsigned bundle.
func (p publisher) publish(ctx context.Context, u *bundles.Unsigned, pp publishParams) (result, []byte, error) {
	if err := checkChangeID(pp.ChangeID); err != nil {
		return result{}, nil, err
	}
	row, err := readDesired(ctx, p.db, pp.Environment)
	if err != nil {
		return result{}, nil, err
	}
	if row != nil {
		return p.reuse(ctx, *row, u.CandidateDigest, pp)
	}
	s, err := signAndVerify(u, p.key, pp.KeyID, pp.Revision)
	if err != nil {
		return result{}, nil, err
	}
	if err := upload(ctx, p.store, pp.Bucket, s.ArtifactDigest, s.Tarball); err != nil {
		return result{}, nil, err
	}
	res := result{
		BundleID: pp.BundleID, Revision: pp.Revision, KeyID: pp.KeyID,
		CandidateDigest: s.CandidateDigest, ArtifactDigest: s.ArtifactDigest,
		ObjectURI: objectURI(pp.Bucket, s.ArtifactDigest), Environment: pp.Environment,
		Published: true,
	}
	inserted, err := insertDesired(ctx, p.db, desiredRow{
		Environment: pp.Environment, BundleID: pp.BundleID, ArtifactDigest: s.ArtifactDigest,
		ObjectURI: res.ObjectURI, SetByChangeID: pp.ChangeID,
	})
	if err != nil {
		return result{}, nil, err
	}
	if inserted {
		return res, s.Tarball, nil
	}
	// Another run inserted between 2 and 6. The object just uploaded stays
	// unreferenced; the winner's row is accepted only under the reuse rules.
	row, err = readDesired(ctx, p.db, pp.Environment)
	if err != nil {
		return result{}, nil, err
	}
	if row == nil {
		return result{}, nil, fmt.Errorf("desired_bundle for %q: insert conflicted but no row found", pp.Environment)
	}
	return p.reuse(ctx, *row, u.CandidateDigest, pp)
}

// reuse accepts an existing desired_bundle row as this run's result if it
// holds the same bundle (package comment). It reads the object but never
// changes the row or the object.
func (p publisher) reuse(ctx context.Context, row desiredRow, candidateDigest string, pp publishParams) (result, []byte, error) {
	refuse := func(format string, a ...any) (result, []byte, error) {
		return result{}, nil, fmt.Errorf("desired_bundle for %q is already set to %s (%s) and is not this bundle: %s; first-bundle does not replace it, use the releaser",
			row.Environment, row.ArtifactDigest, row.BundleID, fmt.Sprintf(format, a...))
	}
	switch {
	case row.Environment != pp.Environment:
		return refuse("environment %q", row.Environment)
	case row.BundleID != pp.BundleID:
		return refuse("bundle_id %q, want %q", row.BundleID, pp.BundleID)
	case row.SetByChangeID != pp.ChangeID:
		return refuse("set_by_change_id %s, want %s", row.SetByChangeID, pp.ChangeID)
	case !digestPattern.MatchString(row.ArtifactDigest) || row.ObjectURI != objectURI(pp.Bucket, row.ArtifactDigest):
		return refuse("object_uri %s, want %s", row.ObjectURI, objectURI(pp.Bucket, row.ArtifactDigest))
	}
	b, err := p.store.read(ctx, pp.Bucket, objectName(row.ArtifactDigest))
	if err != nil {
		return refuse("read %s: %v", row.ObjectURI, err)
	}
	if got := bundles.ArtifactDigest(b); got != row.ArtifactDigest {
		return refuse("object has SHA-256 %s", got)
	}
	rev, err := bundles.Verify(b, p.key.PublicKeyPEM(), pp.KeyID)
	if err != nil {
		return refuse("%v", err)
	}
	if rev != pp.Revision {
		return refuse("verified revision %q, want %q", rev, pp.Revision)
	}
	// Only after Verify: the files are now known to be the signed ones.
	cd, err := bundles.SignedCandidateDigest(b)
	if err != nil {
		return refuse("%v", err)
	}
	if cd != candidateDigest {
		return refuse("candidate_digest %s, want %s", cd, candidateDigest)
	}
	return result{
		BundleID: row.BundleID, Revision: rev, KeyID: pp.KeyID,
		CandidateDigest: cd, ArtifactDigest: row.ArtifactDigest,
		ObjectURI: row.ObjectURI, Environment: row.Environment,
		Published: true,
	}, b, nil
}

// upload writes the object only if it does not exist. An existing object with
// this content-addressed name must have the same bytes.
func upload(ctx context.Context, store objectStore, bucket, artifactDigest string, tarball []byte) error {
	existed, err := store.createIfAbsent(ctx, bucket, objectName(artifactDigest), tarball)
	if err != nil || !existed {
		return err
	}
	b, err := store.read(ctx, bucket, objectName(artifactDigest))
	if err != nil {
		return err
	}
	if got := bundles.ArtifactDigest(b); got != artifactDigest {
		return fmt.Errorf("existing object has SHA-256 %s, want %s", got, artifactDigest)
	}
	return nil
}

type gcsStore struct{ client *storage.Client }

func (g gcsStore) createIfAbsent(ctx context.Context, bucket, name string, body []byte) (bool, error) {
	w := g.client.Bucket(bucket).Object(name).If(storage.Conditions{DoesNotExist: true}).NewWriter(ctx)
	w.ContentType = "application/gzip"
	w.SendCRC32C = true
	w.CRC32C = crc32c(body)
	if _, err := w.Write(body); err != nil {
		_ = w.Close()
		return false, err
	}
	err := w.Close()
	var gerr *googleapi.Error
	if errors.As(err, &gerr) && gerr.Code == http.StatusPreconditionFailed {
		return true, nil
	}
	return false, err
}

func (g gcsStore) read(ctx context.Context, bucket, name string) ([]byte, error) {
	r, err := g.client.Bucket(bucket).Object(name).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxObjectBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxObjectBytes {
		return nil, fmt.Errorf("gs://%s/%s is larger than %d bytes", bucket, name, maxObjectBytes)
	}
	return b, nil
}

// desiredRow is a release.desired_bundle row without set_at.
type desiredRow struct {
	Environment, BundleID, ArtifactDigest, ObjectURI, SetByChangeID string
}

// readDesired returns the environment's row, or nil if there is none.
func readDesired(ctx context.Context, db *pgx.Conn, environment string) (*desiredRow, error) {
	var r desiredRow
	err := db.QueryRow(ctx, `
SELECT environment, bundle_id, artifact_digest, object_uri, set_by_change_id::text
FROM release.desired_bundle WHERE environment = $1`, environment).
		Scan(&r.Environment, &r.BundleID, &r.ArtifactDigest, &r.ObjectURI, &r.SetByChangeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// insertDesired writes the first desired_bundle row of the environment and
// reports whether it did. It never changes an existing row: changing it is an
// activation, which must go through the releaser (hold → desired_bundle →
// lease ack → epoch CAS).
func insertDesired(ctx context.Context, db *pgx.Conn, r desiredRow) (bool, error) {
	tag, err := db.Exec(ctx, `
INSERT INTO release.desired_bundle (environment, bundle_id, artifact_digest, object_uri, set_by_change_id, set_at)
VALUES ($1, $2, $3, $4, $5::uuid, statement_timestamp())
ON CONFLICT (environment) DO NOTHING`,
		r.Environment, r.BundleID, r.ArtifactDigest, r.ObjectURI, r.SetByChangeID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
