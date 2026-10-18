package store

import (
	"context"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	corev1 "k8s.io/api/core/v1"
)

// The production KubeNodeFacts adapter against a local HTTPS Node API and the
// real first-sensor-lease transaction. GKE Node behavior is not exercised.
func testPostgresKubeNodeFacts(t *testing.T, base *Store, db *pgx.Conn) {
	t.Helper()
	ctx := context.Background()
	san := "spiffe://agentarium.internal/ns/agent-sensors/sa/sensor-exporter"
	register := func(t *testing.T, s *Store, nodeUID, certBoot string) (health.LeaseAck, error) {
		t.Helper()
		sn := "nf" + uuid.NewString()[:6]
		if _, err := db.Exec(ctx, "INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,node_uid,boot_id,issued_at,expires_at) VALUES($1,$2,'agent-sensors','sensor-exporter',$3,$4,now()-interval '1 minute',now()+interval '1 hour')", sn, san, nodeUID, certBoot); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		gen := int64(1)
		return s.Put(ctx, health.Peer{SAN: san, Serial: sn}, health.Lease{SourceID: "tetragon-node/" + nodeUID, Component: "node-sensors", Scope: "node", ScopeID: nodeUID,
			SensorGeneration: &gen, ReportedAt: now, LeaseUntil: now.Add(15 * time.Second), ObservedState: "healthy"})
	}
	row := func(t *testing.T, nodeUID string) (capture, measurement string, n int) {
		t.Helper()
		if err := db.QueryRow(ctx, "SELECT count(*) FROM health.node_boot_generation WHERE node_uid=$1", nodeUID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			if err := db.QueryRow(ctx, "SELECT startup_capture,startup_capture_measurement FROM health.node_boot_generation WHERE node_uid=$1", nodeUID).Scan(&capture, &measurement); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	stale := q0Runtime
	stale.KernelVersion = "6.6.99+"
	cases := []struct {
		name     string
		node     func(uid string) corev1.Node
		certBoot string
		swapUID  bool
		capture  string
		measured string
	}{
		{"measured guarded", func(uid string) corev1.Node { return node("n-g", uid, "exec-pool", "boot-1", q0Runtime) }, "boot-1", false, "guarded", Measured},
		{"missing q0 recorded not_measured", func(uid string) corev1.Node { return node("n-u", uid, "control-pool", "boot-1", stale) }, "boot-1", false, "unsupported", NotMeasured},
		{"boot changed", func(uid string) corev1.Node { return node("n-b", uid, "exec-pool", "boot-2", q0Runtime) }, "boot-1", false, "", ""},
		{"uid swapped", func(uid string) corev1.Node { return node("n-s", uid, "exec-pool", "boot-1", q0Runtime) }, "boot-1", true, "", ""},
		{"stale profile", func(uid string) corev1.Node { return node("n-p", uid, "exec-pool", "boot-1", stale) }, "boot-1", false, "", ""},
		{"wrong pool", func(uid string) corev1.Node { return node("n-w", uid, "system-pool", "boot-1", q0Runtime) }, "boot-1", false, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			uid := uuid.NewString()
			api, client := newNodeAPI(t, c.node(uid))
			if c.swapUID {
				api.getUID[c.node(uid).Name] = "6f1f0a0e-0000-4000-8000-0000000000ee"
			}
			s := *base
			s.NodeFacts = KubeNodeFacts{Client: client, Rows: lockRows(t)}
			_, err := register(t, &s, uid, c.certBoot)
			capture, measurement, n := row(t, uid)
			if c.capture == "" {
				if err == nil || n != 0 {
					t.Fatalf("rejected case registered: err=%v rows=%d", err, n)
				}
				return
			}
			if err != nil || n != 1 || capture != c.capture || measurement != c.measured {
				t.Fatalf("err=%v rows=%d capture=%s measurement=%s", err, n, capture, measurement)
			}
			if len(api.denied) != 0 {
				t.Fatalf("requests outside nodes get/list: %v", api.denied)
			}
		})
	}
	t.Run("schema rejects guarded without measurement", func(t *testing.T) {
		for _, q := range []string{
			"INSERT INTO health.node_boot_generation(node_uid,boot_id,startup_capture,state,updated_at,startup_capture_measurement) VALUES(gen_random_uuid(),'x','guarded','preparing',now(),'not_measured')",
			"INSERT INTO health.node_boot_generation(node_uid,boot_id,startup_capture,state,updated_at) VALUES(gen_random_uuid(),'x','unsupported','preparing',now())",
		} {
			if _, err := db.Exec(ctx, q); err == nil {
				t.Fatalf("schema accepted %s", q)
			}
		}
	})
}
