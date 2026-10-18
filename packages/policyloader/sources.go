package policyloader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DesiredBundleTable is the TASK-14 table this package reads.
// SPEC-QUESTION: the schema name ("release") is decided in PR #31; if it
// changes, change this constant and the integration test.
const DesiredBundleTable = "release.desired_bundle"

// PGSource reads this environment's desired_bundle row.
type PGSource struct {
	Pool        *pgxpool.Pool
	Environment string
}

// ErrNoDesiredBundle means the environment has no desired_bundle row yet.
var ErrNoDesiredBundle = errors.New("policyloader: no desired_bundle row")

func (s PGSource) Desired(ctx context.Context) (Desired, error) {
	var d Desired
	err := s.Pool.QueryRow(ctx,
		`SELECT bundle_id, artifact_digest, object_uri FROM `+DesiredBundleTable+` WHERE environment = $1`,
		s.Environment).Scan(&d.BundleID, &d.ArtifactDigest, &d.ObjectURI)
	if errors.Is(err, pgx.ErrNoRows) {
		return Desired{}, ErrNoDesiredBundle
	}
	return d, err
}

// GCSFetcher reads gs:// objects. The storage client's own retries are
// allowed here: this is an internal infrastructure read, not an external
// action (TASK-04 3.1).
type GCSFetcher struct {
	Client *storage.Client
}

func (f GCSFetcher) Fetch(ctx context.Context, uri string) ([]byte, error) {
	rest, ok := strings.CutPrefix(uri, "gs://")
	bucket, object, ok2 := strings.Cut(rest, "/")
	if !ok || !ok2 || bucket == "" || object == "" {
		return nil, fmt.Errorf("policyloader: bad gs:// URI %q", uri)
	}
	r, err := f.Client.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, MaxObjectBytes+1))
	if err != nil {
		return nil, err
	}
	return b, nil
}
