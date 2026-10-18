//go:build integration

package main

// Local M3-1 end-to-end harness (tests/m3-1/run-local.sh). The CLI signs with
// Cloud KMS, which a laptop does not have. This test runs the same publish
// path (buildBundle, publisher.publish with gcsStore against the bucket named
// by STORAGE_EMULATOR_HOST, desired_bundle insert) with one test-only change
// confined to this file: the signing key is a fresh in-memory ECDSA P-256 key
// (localKey) instead of a KMS key version. Its public key is written to
// M31_BUNDLE_PUBLIC_KEY_FILE for the services' --bundle-key-file; the private
// key never leaves the process.
//
// It runs only when M31_BUNDLE_HARNESS is set.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

func TestM31LocalBundleHarness(t *testing.T) {
	if os.Getenv("M31_BUNDLE_HARNESS") == "" {
		t.Skip("M31_BUNDLE_HARNESS not set (tests/m3-1/run-local.sh)")
	}
	get := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			t.Fatalf("%s is required", k)
		}
		return v
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	u, err := buildBundle(get("M31_BUNDLE_POLICY_DIR"), get("M31_BUNDLE_CATALOG_DIR"), get("M31_BUNDLE_POLICY_DATA"), get("M31_BUNDLE_REVISION"), true)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := canonical.LoadCatalogDir(get("M31_BUNDLE_CATALOG_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	key := newLocalKey(t)
	if err := os.WriteFile(get("M31_BUNDLE_PUBLIC_KEY_FILE"), []byte(key.PublicKeyPEM()), 0o644); err != nil {
		t.Fatal(err)
	}
	gcs, err := storage.NewClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gcs.Close()
	conn, err := pgx.Connect(ctx, get("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	p := publisher{key: key, store: gcsStore{gcs}, db: conn}
	res, _, err := p.publish(ctx, u, publishParams{
		BundleID: get("M31_BUNDLE_ID"), Revision: get("M31_BUNDLE_REVISION"), KeyID: "prod-v1",
		Bucket: get("M31_BUNDLE_BUCKET"), Environment: get("M31_BUNDLE_ENVIRONMENT"), ChangeID: get("M31_BUNDLE_CHANGE_ID"),
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(struct {
		result
		CatalogDigest string `json:"catalog_digest"`
	}{res, cat.CatalogDigest})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(get("M31_BUNDLE_RESULT_FILE"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}
