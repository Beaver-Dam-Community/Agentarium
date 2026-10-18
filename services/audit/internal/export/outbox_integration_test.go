package export

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/healthreport"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type publisherFunc func(context.Context, *Claim, []byte, []Source) (Receipt, error)

func (f publisherFunc) Ready(context.Context, string) error { return nil }

func (f publisherFunc) Publish(ctx context.Context, c *Claim, b []byte, s []Source) (Receipt, error) {
	return f(ctx, c, b, s)
}

func TestOutboxPostgres(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	exec := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	name := "export_worker_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	exec(admin, "CREATE DATABASE "+name)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = name
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { db.Close(ctx); _, _ = admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)") }()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../../../..")
	paths, err := filepath.Glob(filepath.Join(root, "migrations/*_audit_store.up.sql"))
	if err != nil || len(paths) != 1 {
		t.Fatal("audit migration missing")
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	exec(db, string(raw))
	// TASK-07 3.2.1 coverage/lease objects build on the audit store.
	leasePaths, err := filepath.Glob(filepath.Join(root, "migrations/*_audit_export_coverage_lease.up.sql"))
	if err != nil || len(leasePaths) != 1 {
		t.Fatal("coverage/lease migration missing")
	}
	raw, err = os.ReadFile(leasePaths[0])
	if err != nil {
		t.Fatal(err)
	}
	exec(db, string(raw))
	pc, err := pgxpool.ParseConfig(cfg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.Database = name
	pc.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE audit_exporter")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	out := Outbox{Pool: pool}
	seed := func(n int) {
		t.Helper()
		exec(db, "TRUNCATE audit.export_manifests,audit.manifest_intents,audit.export_batch_members,audit.export_batches,audit.audit_outbox,audit.audit_events CASCADE")
		for i := 0; i < n; i++ {
			id := uuid.NewString()
			exec(db, `INSERT INTO audit.audit_events(event_id,event_type,tenant,source_id,source_version,source_epoch,source_sequence,source_time,received_at,schema_version,payload_digest,safe_payload) VALUES($1,'request_received','t','producer','v1','epoch',$2,statement_timestamp(),statement_timestamp(),1,$3,'{}')`, id, i+1, strings.Repeat("a", 64))
			exec(db, `INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state) VALUES('audit_event',$1,'gcs','business',50,'pending')`, id)
		}
	}
	claim := func() *Claim {
		t.Helper()
		c, err := out.Claim(ctx, "gcs", "business")
		if err != nil || c == nil {
			t.Fatalf("claim: %v %v", c, err)
		}
		return c
	}
	expire := func() {
		exec(db, "UPDATE audit.audit_outbox SET lease_until=statement_timestamp()-interval '1 second',next_retry_at=statement_timestamp()-interval '1 second'")
	}
	receipt := func(c *Claim) Receipt {
		t.Helper()
		data, _, err := out.Records(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		r := Receipt{Generation: 123, BatchDigest: Digest(data), ManifestDigest: strings.Repeat("b", 64)}
		var token int64
		if err := db.QueryRow(ctx, "SELECT fencing_token FROM audit.acquire_manifest_lease('gcs',$1)", testLeaseHolder).Scan(&token); err != nil {
			t.Fatal(err)
		}
		exec(db, "INSERT INTO audit.manifest_intents(chain_id,manifest_seq,batch_id,fencing_token) VALUES('gcs',1,$1,$2)", c.BatchID, token)
		exec(db, `INSERT INTO audit.export_manifests(chain_id,manifest_seq,object_generation,batch_digest,manifest_digest,kms_key_version,signature,manifest_object_key,fencing_token) VALUES('gcs',1,$1,$2,$3,'test-key','\x01','manifests/1.json',$4)`, r.Generation, r.BatchDigest, r.ManifestDigest, token)
		return r
	}
	stateCount := func(state string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_outbox WHERE state=$1", state).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Run("concurrent workers partition max100", func(t *testing.T) {
		seed(150)
		var wg sync.WaitGroup
		cs := make(chan *Claim, 2)
		es := make(chan error, 2)
		for range 2 {
			wg.Add(1)
			go func() { defer wg.Done(); c, e := out.Claim(ctx, "gcs", "business"); cs <- c; es <- e }()
		}
		wg.Wait()
		close(cs)
		close(es)
		for e := range es {
			if e != nil {
				t.Fatal(e)
			}
		}
		total := 0
		ids := map[string]bool{}
		for c := range cs {
			if c == nil || c.Count() > 100 || ids[c.BatchID] {
				t.Fatal("invalid concurrent claim")
			}
			ids[c.BatchID] = true
			total += c.Count()
		}
		if total != 150 || stateCount("claimed") != 150 {
			t.Fatal("members lost or duplicated")
		}
		if c, e := out.Claim(ctx, "gcs", "business"); e != nil || c != nil {
			t.Fatal("live claims reclaimed")
		}
	})
	t.Run("partial lock skip and lease recovery fencing", func(t *testing.T) {
		seed(2)
		old := claim()
		expire()
		lock, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = lock.Exec(ctx, "SELECT FROM audit.audit_outbox WHERE record_id=$1 FOR UPDATE", old.members[1].RecordID); err != nil {
			t.Fatal(err)
		}
		c, e := out.Claim(ctx, "gcs", "business")
		if e != nil || c != nil {
			t.Fatalf("partial batch claimed: %v %v", c, e)
		}
		if err = lock.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		current := claim()
		if current.BatchID != old.BatchID || current.ObjectKey != old.ObjectKey || current.Count() != 2 {
			t.Fatal("recovery changed fixed batch")
		}
		if err = out.Retry(ctx, old); !errors.Is(err, ErrClaimLost) {
			t.Fatalf("stale retry %v", err)
		}
		r := receipt(current)
		if err = out.Ack(ctx, old, r); !errors.Is(err, ErrClaimLost) {
			t.Fatalf("stale ack %v", err)
		}
		wrong := r
		wrong.Generation++
		if err = out.Ack(ctx, current, wrong); !errors.Is(err, ErrManifestMissing) {
			t.Fatalf("wrong receipt %v", err)
		}
		if stateCount("claimed") != 2 {
			t.Fatal("failed ack changed state")
		}
		if err = out.Ack(ctx, current, r); err != nil {
			t.Fatal(err)
		}
		if stateCount("acked") != 2 {
			t.Fatal("partial ack")
		}
		var ref string
		if err = db.QueryRow(ctx, "SELECT ack_ref FROM audit.audit_outbox LIMIT 1").Scan(&ref); err != nil || ref != current.ObjectKey+"#123" {
			t.Fatalf("ref %q %v", ref, err)
		}
	})
	t.Run("manifest required and ack rollback", func(t *testing.T) {
		seed(2)
		c := claim()
		r := Receipt{Generation: 123, BatchDigest: strings.Repeat("a", 64), ManifestDigest: strings.Repeat("b", 64)}
		if err = out.Ack(ctx, c, r); !errors.Is(err, ErrManifestMissing) {
			t.Fatalf("uncommitted manifest: %v", err)
		}
		r = receipt(c)
		exec(db, `CREATE FUNCTION audit.test_ack_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='acked' AND NEW.record_id=`+fmt.Sprintf("'%s'", c.members[1].RecordID)+` THEN RAISE EXCEPTION 'injected ack failure'; END IF; RETURN NEW; END $$`)
		exec(db, `CREATE TRIGGER test_ack_failure BEFORE UPDATE ON audit.audit_outbox FOR EACH ROW EXECUTE FUNCTION audit.test_ack_failure()`)
		if err = out.Ack(ctx, c, r); err == nil {
			t.Fatal("injected failure ignored")
		}
		if stateCount("claimed") != 2 {
			t.Fatal("transaction partially committed")
		}
		exec(db, "DROP TRIGGER test_ack_failure ON audit.audit_outbox")
		exec(db, "DROP FUNCTION audit.test_ack_failure()")
	})
	t.Run("retry schedule and stable identity", func(t *testing.T) {
		seed(1)
		c := claim()
		id := c.BatchID
		for attempt, want := range []int{1, 2, 4, 8, 16, 30, 30} {
			if err = out.Retry(ctx, c); err != nil {
				t.Fatal(err)
			}
			var delay float64
			if err = db.QueryRow(ctx, "SELECT extract(epoch from next_retry_at-statement_timestamp()) FROM audit.audit_outbox").Scan(&delay); err != nil {
				t.Fatal(err)
			}
			if delay > float64(want) || delay < float64(want)-1 {
				t.Fatalf("attempt %d delay %f want %d", attempt+1, delay, want)
			}
			if next, e := out.Claim(ctx, "gcs", "business"); e != nil || next != nil {
				t.Fatal("backoff ignored")
			}
			expire()
			c = claim()
			if c.BatchID != id {
				t.Fatal("retry changed batch")
			}
		}
	})
	t.Run("worker durable receipt and retry", func(t *testing.T) {
		seed(2)
		w := Worker{Outbox: out, Publisher: publisherFunc(func(_ context.Context, c *Claim, data []byte, sources []Source) (Receipt, error) {
			if c.Count() != 2 || len(sources) != 1 || sources[0].First != 1 || sources[0].Last != 2 {
				t.Fatal("wrong fixed records")
			}
			r := receipt(c)
			if r.BatchDigest != Digest(data) {
				t.Fatal("nonstable bytes")
			}
			return r, nil
		})}
		if worked, e := w.Once(ctx); e != nil || !worked || stateCount("acked") != 2 {
			t.Fatalf("worker ack: %v %v", worked, e)
		}
		seed(2)
		w.Publisher = publisherFunc(func(context.Context, *Claim, []byte, []Source) (Receipt, error) {
			return Receipt{}, errors.New("upload failed")
		})
		if worked, e := w.Once(ctx); e == nil || !worked || stateCount("pending") != 2 || stateCount("acked") != 0 {
			t.Fatalf("worker failure: %v %v", worked, e)
		}
	})
	t.Run("publisher actual SDK chain and crash recovery", func(t *testing.T) {
		seed(1)
		cloud := newPublisherCloud(t)
		pub := ManifestPublisher{Pool: pool, Objects: cloud.Objects, Signer: cloud.Signer, KeyVersion: cloud.Version, Keys: map[string]*ecdsa.PublicKey{cloud.Version: cloud.Key}, Leader: liveLease(pool)}
		c := claim()
		data, sources, e := out.Records(ctx, c)
		if e != nil {
			t.Fatal(e)
		}
		// Crash boundary: GCS accepted manifest bytes, then DB commit fails.
		exec(db, `CREATE FUNCTION audit.test_manifest_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'crash after upload'; END $$`)
		exec(db, `CREATE TRIGGER test_manifest_failure BEFORE INSERT ON audit.export_manifests FOR EACH ROW EXECUTE FUNCTION audit.test_manifest_failure()`)
		if _, e = pub.Publish(ctx, c, data, sources); e == nil {
			t.Fatal("injected crash ignored")
		}
		if n, signs := cloud.counts(); n != 2 || signs != 1 {
			t.Fatalf("upload/sign boundary: %d %d", n, signs)
		}
		var intents int
		if e = db.QueryRow(ctx, "SELECT count(*) FROM audit.manifest_intents").Scan(&intents); e != nil || intents != 1 {
			t.Fatalf("intent not durable: %d %v", intents, e)
		}
		exec(db, "DROP TRIGGER test_manifest_failure ON audit.export_manifests")
		exec(db, "DROP FUNCTION audit.test_manifest_failure()")
		expire()
		c = claim()
		r, e := pub.Publish(ctx, c, data, sources)
		if e != nil {
			t.Fatal(e)
		}
		if n, signs := cloud.counts(); n != 2 || signs != 1 {
			t.Fatalf("recovery signed/created twice: %d %d", n, signs)
		}
		if e = out.Ack(ctx, c, r); e != nil {
			t.Fatal(e)
		}
		raw, e := cloud.Objects.ReadManifest(ctx, "manifests/1.json")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = Verify(ctx, raw, 1, nil, pub.Keys, cloud.Objects, PGAcks{Queries: auditdb.New(pool), Destination: "gcs"}); e != nil {
			t.Fatal(e)
		}
		// A second batch extends the chain and preserves the first digest.
		id := uuid.NewString()
		exec(db, `INSERT INTO audit.audit_events(event_id,event_type,tenant,source_id,source_version,source_epoch,source_sequence,source_time,received_at,schema_version,payload_digest,safe_payload) VALUES($1,'request_received','t','producer','v1','epoch',2,statement_timestamp(),statement_timestamp(),1,$2,'{}')`, id, strings.Repeat("a", 64))
		exec(db, `INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state) VALUES('audit_event',$1,'gcs','business',50,'pending')`, id)
		if worked, e := (Worker{Outbox: out, Publisher: pub}).Once(ctx); e != nil || !worked {
			t.Fatalf("worker publish: %v %v", worked, e)
		}
		second, e := cloud.Objects.ReadManifest(ctx, "manifests/2.json")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = Verify(ctx, second, 2, &r.ManifestDigest, pub.Keys, cloud.Objects, PGAcks{Queries: auditdb.New(pool), Destination: "gcs"}); e != nil {
			t.Fatal(e)
		}
		if n, signs := cloud.counts(); n != 4 || signs != 2 {
			t.Fatalf("chain counts: %d %d", n, signs)
		}
	})
	t.Run("kernel and lifecycle publication", func(t *testing.T) {
		for _, class := range []string{"kernel", "lifecycle"} {
			t.Run(class, func(t *testing.T) {
				seed(0)
				exec(db, "TRUNCATE audit.watch_checkpoints,audit.kernel_events,audit.lifecycle_events")
				kind, eventType := "kernel_event", "kernel_event_observed"
				if class == "lifecycle" {
					kind, eventType = "lifecycle_event", "lifecycle_recorded"
				}
				for _, seq := range []int{3, 1} {
					id := uuid.NewString()
					if class == "kernel" {
						exec(db, `INSERT INTO audit.kernel_events(source_event_id,source_id,sensor_id,source_epoch,source_sequence,exporter_instance_id,sensor_generation,node_uid,boot_id,source_time,spooled_at,received_at,event_type,process_exec_id,metadata_status,normalization_version,rule_hash,coverage,safe_attributes,record_digest)
     VALUES($1,'sensor-source','sensor','epoch',$2,'exporter',1,gen_random_uuid(),'boot',now(),now(),now(),'process_exec','exec','fixture','v1',$3,'fixture','{}',$3)`, id, seq, strings.Repeat("a", 64))
					} else {
						exec(db, `INSERT INTO audit.lifecycle_events(lifecycle_event_id,source_id,source_kind,source_epoch,source_sequence,cluster_uid,pod_uid,namespace,pod_name,node_uid,boot_id,transition,received_at,mapping_version,record_digest)
     VALUES($1,'runtime-source','runtime','epoch',$2,gen_random_uuid(),gen_random_uuid(),'agent-exec','synthetic',gen_random_uuid(),'boot','fixture',now(),1,$3)`, id, seq, strings.Repeat("b", 64))
					}
					exec(db, `INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state) VALUES($1,$2,'gcs',$3,100,'pending')`, kind, id, class)
				}
				cloud := newPublisherCloud(t)
				pub := ManifestPublisher{Pool: pool, Objects: cloud.Objects, Signer: cloud.Signer, KeyVersion: cloud.Version, Keys: map[string]*ecdsa.PublicKey{cloud.Version: cloud.Key}, Leader: liveLease(pool)}
				if worked, err := (Worker{Outbox: out, Publisher: pub, SourceClass: class}).Once(ctx); err != nil || !worked {
					t.Fatalf("%s worker: %v %v", class, worked, err)
				}
				raw, err := cloud.Objects.ReadManifest(ctx, "manifests/1.json")
				if err != nil {
					t.Fatal(err)
				}
				env, err := Decode(raw)
				if err != nil {
					t.Fatal(err)
				}
				m := env.Manifest
				if len(m.Sources) != 1 || m.Sources[0].First != 1 || m.Sources[0].Last != 3 || m.RecordCount != 2 {
					t.Fatalf("wrong ranges: %+v", m)
				}
				data, err := cloud.Objects.Read(ctx, m.ObjectKey, m.Generation)
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
					var record Record
					if err := json.Unmarshal([]byte(line), &record); err != nil {
						t.Fatal(err)
					}
					if record.Kind != kind || record.EventType != eventType {
						t.Fatal("wrong observation wrapper")
					}
				}
				if _, err := Verify(ctx, raw, 1, nil, pub.Keys, cloud.Objects, PGAcks{Queries: auditdb.New(pool), Destination: "gcs"}); err != nil {
					t.Fatal(err)
				}
			})
		}
	})
	t.Run("actual backlog lease and hold reporting", func(t *testing.T) {
		seed(2)
		exec(db, "UPDATE audit.audit_outbox SET enqueued_at=statement_timestamp()-interval '121 seconds',record_bytes=123")
		rows, err := auditdb.New(pool).ExportBacklogs(ctx)
		if err != nil || len(rows) != 1 || rows[0].PendingRecords != 2 || rows[0].PendingBytes != 246 || rows[0].OldestAgeSeconds < 121 {
			t.Fatalf("actual backlog: %+v %v", rows, err)
		}
		var leases []healthreport.Lease
		holds := 0
		deny := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Error("unexpected method")
			}
			switch r.URL.Path {
			case "/internal/holds":
				var request struct {
					Scope    string   `json:"scope"`
					ScopeID  string   `json:"scope_id"`
					Reason   string   `json:"reason"`
					Evidence []string `json:"evidence_refs"`
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil || request.Scope != "global" || request.ScopeID != "*" || request.Reason != "export_lag" || request.Evidence == nil {
					t.Error("wrong export hold request")
				}
				holds++
				if deny {
					w.WriteHeader(403)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"hold_id": uuid.NewString(), "decision": "existing", "reason_codes": []string{}})
			case "/internal/control-health/leases":
				var lease healthreport.Lease
				if json.NewDecoder(r.Body).Decode(&lease) != nil {
					t.Error("invalid lease")
				}
				leases = append(leases, lease)
				_ = json.NewEncoder(w).Encode(map[string]any{"lease_until": lease.LeaseUntil, "scope_state": "unhealthy"})
			default:
				t.Error("unexpected path")
				w.WriteHeader(404)
			}
		}))
		defer srv.Close()
		reporter := HealthReporter{Pool: pool, Client: srv.Client(), URL: srv.URL, SourceID: "exporter-test", Version: "v1"}
		if err := reporter.Report(ctx); err != nil {
			t.Fatal(err)
		}
		if holds != 1 || len(leases) != 1 || leases[0].Component != "audit-export" || leases[0].Scope != "global" || leases[0].ObservedState != "degraded" || leases[0].LeaseUntil.Sub(leases[0].ReportedAt) != 15*time.Second {
			t.Fatalf("report: %d %+v", holds, leases)
		}
		deny = true
		if err := reporter.Report(ctx); err == nil {
			t.Fatal("hold rejection ignored")
		}
		if leases[len(leases)-1].ObservedState != "unhealthy" {
			t.Fatal("failed required hold did not fail closed")
		}
		exec(db, "UPDATE audit.audit_outbox SET state='acked'")
		if err := reporter.Report(ctx); err != nil {
			t.Fatal(err)
		}
		if holds != 2 || leases[len(leases)-1].ObservedState != "healthy" {
			t.Fatal("acked rows counted or automatic release attempted")
		}
	})
	t.Run("publisher cannot skip unfinished predecessor", func(t *testing.T) {
		seed(101)
		cloud := newPublisherCloud(t)
		pub := ManifestPublisher{Pool: pool, Objects: cloud.Objects, Signer: signerFunc(func(context.Context, []byte) ([]byte, error) { return nil, errors.New("KMS unavailable") }), KeyVersion: cloud.Version, Keys: map[string]*ecdsa.PublicKey{cloud.Version: cloud.Key}, Leader: liveLease(pool)}
		first, second := claim(), claim()
		data1, sources1, e := out.Records(ctx, first)
		if e != nil {
			t.Fatal(e)
		}
		data2, sources2, e := out.Records(ctx, second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pub.Publish(ctx, first, data1, sources1); e == nil {
			t.Fatal("missing signer result accepted")
		}
		pub.Signer = cloud.Signer
		if _, e = pub.Publish(ctx, second, data2, sources2); !errors.Is(e, ErrManifestChainBusy) {
			t.Fatalf("unfinished predecessor skipped: %v", e)
		}
		var n int
		if e = db.QueryRow(ctx, "SELECT count(*) FROM audit.manifest_intents").Scan(&n); e != nil || n != 1 {
			t.Fatalf("sequence reserved past gap: %d %v", n, e)
		}
		if _, e = pub.Publish(ctx, first, data1, sources1); e != nil {
			t.Fatal(e)
		}
		if _, e = pub.Publish(ctx, second, data2, sources2); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("publisher signature and lost lease reject commit", func(t *testing.T) {
		seed(1)
		cloud := newPublisherCloud(t)
		checks := 0
		live := liveLease(pool)
		pub := ManifestPublisher{Pool: pool, Objects: cloud.Objects, Signer: cloud.Signer, KeyVersion: cloud.Version, Keys: map[string]*ecdsa.PublicKey{cloud.Version: cloud.Key}, Leader: leaseFunc(func(ctx context.Context, chain string) (int64, error) {
			checks++
			if checks == 6 {
				return 0, errors.New("lease expired before commit")
			}
			return live(ctx, chain)
		})}
		c := claim()
		data, sources, e := out.Records(ctx, c)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pub.Publish(ctx, c, data, sources); e == nil {
			t.Fatal("expired leader committed")
		}
		var n int
		if e = db.QueryRow(ctx, "SELECT count(*) FROM audit.export_manifests").Scan(&n); e != nil || n != 0 {
			t.Fatalf("lost lease committed manifest: %d %v", n, e)
		}
		pub.Leader = liveLease(pool)
		cloud.mu.Lock()
		original := cloud.objects["manifests/1.json"]
		bad := original
		var env Envelope
		_ = json.Unmarshal(original.data, &env)
		env.Signature = "AA=="
		bad.data, _ = json.Marshal(env)
		cloud.objects["manifests/1.json"] = bad
		cloud.mu.Unlock()
		if _, e = pub.Publish(ctx, c, data, sources); e == nil {
			t.Fatal("corrupt signature reconciled")
		}
		cloud.mu.Lock()
		cloud.objects["manifests/1.json"] = original
		cloud.mu.Unlock()
		if _, e = pub.Publish(ctx, c, data, sources); e != nil {
			t.Fatal(e)
		}
		cloud.mu.Lock()
		delete(cloud.objects, "manifests/1.json")
		cloud.mu.Unlock()
		if _, e = pub.Publish(ctx, c, data, sources); !errors.Is(e, ErrManifestObjectMissing) {
			t.Fatalf("missing committed evidence regenerated: %v", e)
		}
		if n, signs := cloud.counts(); n != 1 || signs != 1 {
			t.Fatalf("committed evidence replacement: %d %d", n, signs)
		}
	})
	t.Run("publisher gate lost and chain lock", func(t *testing.T) {
		seed(1)
		cloud := newPublisherCloud(t)
		pub := ManifestPublisher{Pool: pool, Objects: cloud.Objects, Signer: cloud.Signer, KeyVersion: cloud.Version, Keys: map[string]*ecdsa.PublicKey{cloud.Version: cloud.Key}, Leader: leaseFunc(func(context.Context, string) (int64, error) { return 0, errors.New("lease expired") })}
		c := claim()
		data, sources, e := out.Records(ctx, c)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pub.Publish(ctx, c, data, sources); e == nil {
			t.Fatal("expired leader published")
		}
		if n, _ := cloud.counts(); n != 0 {
			t.Fatal("leader failure had external I/O")
		}
		pub.Leader = liveLease(pool)
		exec(db, "SELECT pg_advisory_lock(1096107076,1)")
		if _, e = pub.Publish(ctx, c, data, sources); !errors.Is(e, ErrManifestChainBusy) {
			t.Fatalf("chain lock ignored: %v", e)
		}
		exec(db, "SELECT pg_advisory_unlock(1096107076,1)")
	})
	t.Run("unsequenced coverage and unwired worker fail closed", func(t *testing.T) {
		seed(1)
		if _, err = (Worker{Outbox: out}).Once(ctx); err == nil || stateCount("pending") != 1 {
			t.Fatal("unwired worker claimed")
		}
		if worked, e := (Worker{Outbox: out, Publisher: ManifestPublisher{Pool: pool}}).Once(ctx); worked || !errors.Is(e, ErrLeaderLeaseMissing) || stateCount("pending") != 1 {
			t.Fatalf("missing leader claimed: %v %v", worked, e)
		}
		c := claim()
		// Unsequenced business rows export without an invented sequence; they
		// contribute no source range (outbox_range covers them, TASK-07 3.2.1).
		exec(db, "UPDATE audit.audit_events SET source_sequence=NULL")
		if _, sources, err := out.Records(ctx, c); err != nil || len(sources) != 0 {
			t.Fatalf("unsequenced export: %v %v", sources, err)
		}
		if _, err = pool.Exec(ctx, "DELETE FROM audit.audit_outbox"); err == nil {
			t.Fatal("exporter DELETE allowed")
		}
		if _, err = pool.Exec(ctx, "UPDATE audit.audit_outbox SET record_bytes=1"); err == nil {
			t.Fatal("exporter original data mutation allowed")
		}
	})
	t.Run("decision input publication", func(t *testing.T) {
		seed(1)
		testDecisionPublication(t, ctx, db, cfg, root)
	})
}
