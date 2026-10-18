//go:build integration

package store

// Lifecycle source service certificates (COMMON "Lifecycle source authentication
// and epoch") are issued through bootstrap with the real store, bound to their
// Pod, and revoked by the revoker once that Pod is gone. Uses the same
// IDENTITY_TEST_DATABASE_URL as TestStore.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/bootstrap"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/issuer"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/pki"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/revoker"
)

const testNodeUID = "99999999-8888-7777-6666-555555555555"

// podCluster answers TokenReview and Pod/Node gets for one Pod per KSA.
type podCluster struct {
	ns, ksa, podUID string
}

func (c *podCluster) ReviewToken(_ context.Context, token string, _ []string) (bootstrap.TokenReview, error) {
	return bootstrap.TokenReview{
		Authenticated: true, Audiences: []string{bootstrap.Audience},
		Username: "system:serviceaccount:" + c.ns + ":" + c.ksa,
		Extra: map[string][]string{
			"authentication.kubernetes.io/pod-uid":  {c.podUID},
			"authentication.kubernetes.io/pod-name": {c.ksa + "-0"},
		},
	}, nil
}

func (c *podCluster) GetPod(_ context.Context, ns, name string) (bootstrap.Pod, error) {
	if ns != c.ns || name != c.ksa+"-0" {
		return bootstrap.Pod{}, bootstrap.ErrNotFound
	}
	return bootstrap.Pod{UID: c.podUID, Namespace: ns, Name: name, ServiceAccount: c.ksa, NodeName: "n1"}, nil
}

func (c *podCluster) GetNode(context.Context, string) (bootstrap.Node, error) {
	return bootstrap.Node{UID: testNodeUID, BootID: "boot-1"}, nil
}

type serialIssuer struct{ serial string }

func (s serialIssuer) Issue(context.Context, issuer.Request) (issuer.Certificate, error) {
	return issuer.Certificate{LeafPEM: "LEAF", Serial: s.serial, NotAfter: time.Now().Add(24 * time.Hour)}, nil
}

func csrPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestLifecycleSourceRevokedOnPodDelete(t *testing.T) {
	url := os.Getenv("IDENTITY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("IDENTITY_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	_, _ = pool.Exec(ctx, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$`)
	_, _ = pool.Exec(ctx, `DROP SCHEMA IF EXISTS identity CASCADE`)
	migrate(t, ctx, pool, "20261014144500_identity_workload_pki.up.sql")
	t.Cleanup(func() { migrate(t, ctx, pool, "20261014144500_identity_workload_pki.down.sql") })

	s := Store{Pool: pool}
	if _, _, err := s.UpsertRegistrations(ctx, []Registration{
		{Namespace: "agent-sensors", KSA: "lifecycle-recorder", Role: pki.RoleService, ServicePrincipal: "lifecycle-recorder"},
		{Namespace: "agent-observe", KSA: "pod-watcher", Role: pki.RoleService, ServicePrincipal: "pod-watcher"},
		{Namespace: "agent-observe", KSA: "control-health", Role: pki.RoleService, ServicePrincipal: "control-health"},
	}); err != nil {
		t.Fatal(err)
	}

	type wl struct{ ns, ksa, pod, serial string }
	recorder := wl{"agent-sensors", "lifecycle-recorder", "aaaaaaaa-0000-0000-0000-000000000001", "a1"}
	watcher := wl{"agent-observe", "pod-watcher", "aaaaaaaa-0000-0000-0000-000000000002", "a2"}
	health := wl{"agent-observe", "control-health", "aaaaaaaa-0000-0000-0000-000000000003", "a3"}
	for _, w := range []wl{recorder, watcher, health} {
		svc := &bootstrap.Service{Cluster: &podCluster{w.ns, w.ksa, w.pod}, Store: s, Issuer: serialIssuer{w.serial}}
		if _, err := svc.Issue(ctx, "token", csrPEM(t)); err != nil {
			t.Fatalf("%s/%s: %v", w.ns, w.ksa, err)
		}
	}

	type row struct {
		san    string
		pod    *string
		node   *string
		boot   *string
		revoke *time.Time
	}
	read := func(serial string) row {
		t.Helper()
		var r row
		if err := pool.QueryRow(ctx,
			`SELECT san_uri, pod_uid::text, node_uid::text, boot_id, revoked_at FROM identity.issued_certificates WHERE serial = $1`,
			serial).Scan(&r.san, &r.pod, &r.node, &r.boot, &r.revoke); err != nil {
			t.Fatalf("read %s: %v", serial, err)
		}
		return r
	}
	for _, w := range []wl{recorder, watcher} {
		r := read(w.serial)
		if r.san != "spiffe://agentarium.internal/ns/"+w.ns+"/sa/"+w.ksa || r.pod == nil || *r.pod != w.pod ||
			r.node == nil || *r.node != testNodeUID || r.boot == nil || *r.boot != "boot-1" || r.revoke != nil {
			t.Fatalf("%s/%s row = %+v", w.ns, w.ksa, r)
		}
	}
	if r := read(health.serial); r.pod != nil {
		t.Fatalf("control-health service certificate recorded with pod uid %s", *r.pod)
	}

	now := time.Now()
	pods, err := s.UnrevokedPods(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []revoker.PodRef{{Namespace: "agent-observe", UID: watcher.pod}, {Namespace: "agent-sensors", UID: recorder.pod}}
	if len(pods) != len(want) || pods[0] != want[0] || pods[1] != want[1] {
		t.Fatalf("unrevoked pods = %v, want %v", pods, want)
	}

	// The lifecycle-recorder Pod is deleted while the watcher Pod lives on;
	// the namespaces are those of the deploy --pod-namespaces argument.
	rv := &revoker.Revoker{Store: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Namespaces: []string{"agent-exec", "agent-control", "agent-adapters", "agent-observe", "agent-release", "agent-targets", "agent-sensors"}}
	if err := rv.Reconcile(ctx, map[string]bool{watcher.pod: true}); err != nil {
		t.Fatal(err)
	}
	if r := read(recorder.serial); r.revoke == nil {
		t.Fatal("lifecycle-recorder certificate not revoked after its Pod was deleted")
	}
	if r := read(watcher.serial); r.revoke != nil {
		t.Fatal("pod-watcher certificate of a live Pod revoked")
	}

	// The delete-event path (RevokePod) revokes the watcher certificate.
	if n, err := s.RevokePod(ctx, watcher.pod, time.Now()); err != nil || n != 1 {
		t.Fatalf("revoke pod-watcher: %d %v", n, err)
	}
	var unrevoked int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM identity.issued_certificates WHERE revoked_at IS NULL AND namespace||'/'||ksa IN ('agent-sensors/lifecycle-recorder','agent-observe/pod-watcher')`).Scan(&unrevoked); err != nil {
		t.Fatal(err)
	}
	if unrevoked != 0 {
		t.Fatalf("%d lifecycle source certificates still unrevoked", unrevoked)
	}
	if r := read(health.serial); r.revoke != nil {
		t.Fatal("control-health certificate revoked")
	}
}
