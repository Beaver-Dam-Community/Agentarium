//go:build integration

package m31

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestM31LocalE2E drives the M3-1 action path on one machine (see
// tests/m3-1/README.md): the real service binaries on PostgreSQL 16 with the
// repository migrations and local mTLS, the real runtime binaries in a
// container, and the simulations listed under "Simulated locally".
//
// It writes the verdict to $M31_E2E_WORK/result: "pass", "blocked_tls" (every
// stage up to the adapter -> receiver send passed and the send failed closed
// with TLS_VERIFY_FAILED), "blocked_preview" (every stage up to the approval
// contract and both fail-closed cases passed; the contract failed closed for
// lack of a content preview) or "fail".
func TestM31LocalE2E(t *testing.T) {
	e := loadEnv(t)
	result := e.path("result")
	writeFile(t, result, []byte("fail\n"), 0o644)
	ps := &procs{}
	defer ps.stopAll()
	ctx, cancel := context.WithCancel(bg())
	defer cancel()

	step("1. Inputs generated at runtime into %s", e.work)
	top := newTopology(t, e)
	caCert, caKey := localCA(t, e)
	oidc, oidcPub := newOIDCKey(t, e)
	claimKey := e.path("cfg", "claim-key")
	writeFile(t, claimKey, []byte(randomHex(32)), 0o600)
	roleMap := e.path("cfg", "role-map.yaml")
	writeFile(t, roleMap, []byte("tenant: "+tenant+"\nusers:\n  - email: "+consoleEmail+"\n    roles: [approver]\n"), 0o600)
	receiverKey := make([]byte, 32)
	_, _ = rand.Read(receiverKey)
	keyDir := e.path("cfg", "receiver-api-key")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(keyDir, "1"), []byte(base64.RawURLEncoding.EncodeToString(receiverKey)), 0o600)
	receiverSecret := "projects/m31-local/secrets/receiver-api-key"
	info("local CA, OIDC test key, claim key, receiver API key (values not printed); node %s boot %s", top.NodeUID, top.BootID)

	step("2. PostgreSQL 16: migrations and install SQL")
	db := installDB(t, e, receiverSecret)
	defer db.Close()

	step("3. GCS emulator buckets and catalog render")
	for _, b := range []string{"m31-bundles", "m31-audit-evidence", "m31-audit-decisions"} {
		createBucket(t, b)
	}
	ports := map[string]string{}
	for _, n := range []string{"identity", "control-health", "audit-writer", "credential-broker", "coordinator", "gateway", "receiver-sender", "receiver"} {
		ports[n] = freePort(t)
	}
	url := func(n string) string { return "https://127.0.0.1:" + ports[n] }
	catalogDir := renderCatalog(t, e, ports["receiver"])

	step("4. Policy bundle (tools/first-bundle publish path, local signer) and first active_policy")
	bundle := publishBundle(t, e, catalogDir)
	installFile(t, e, filepath.Join(e.repo, "deploy/gcp/base/installer/m3-1-first-active-policy.sql"), map[string]string{
		"environment": environment, "bundle_id": bundle.BundleID, "bundle_digest": bundle.CandidateDigest,
		"artifact_digest": bundle.ArtifactDigest, "expected_opa_revision": bundle.Revision,
		"catalog_digest": bundle.CatalogDigest, "change_id": bundle.changeID,
		// No sensor release policies are rendered locally; the value stands in
		// for the lock baseline_digests.sensor_release_policies.
		"sensor_release_policies_digest": fmt.Sprintf("%x", sha256.Sum256([]byte("m31-local sensor_release_policies"))),
	})
	bundleKey := e.path("cfg", "bundle-prod-v1.pem")

	step("5. Services")
	ca := e.path("cfg", "ca.pem")
	identityCfg := e.path("cfg", "identity-harness.json")
	writeJSON(t, identityCfg, map[string]any{
		"listen": "127.0.0.1:" + ports["identity"], "database_url": e.dsn(logins["identity"]), "environment": environment,
		"trust_bundle": ca, "ca_cert": caCert, "ca_key": caKey, "claim_key_file": claimKey,
		"gateway_san": top.pods["gateway"].san(), "oidc_audience": oidcAudience, "oidc_allowed_hd": oidcDomain, "role_map": roleMap,
		"jwks_kid": oidc.kid, "jwks_public_key": oidcPub, "bundle_key_id": "prod-v1", "bundle_key_file": bundleKey,
		"audit_source_id": "workload-identity", "audit_source_version": "m31-local", "epoch_dir": epochDir(t, e, "identity"),
		"tokens": top.tokenTable(), "nodes": map[string]any{nodeName: map[string]string{"uid": top.NodeUID, "boot_id": top.BootID}},
	})
	identity := ps.start(t, e, "identity", filepath.Join(e.bin, "identity.test"), harnessArgs("TestM31LocalIdentityHarness"), "M31_IDENTITY_HARNESS_CONFIG="+identityCfg)
	identityClient := sanClient(t, ca, sanPrefix+"agent-control/sa/workload-identity", nil)
	waitFor(t, "identity /healthz", 60*time.Second, func() error {
		if !identity.alive() {
			t.Fatalf("identity exited:\n%s", identity.tail(30))
		}
		status, _, err := call(identityClient, "GET", url("identity")+"/healthz", "", nil, nil)
		if err != nil || status != 204 {
			return fmt.Errorf("%d %v", status, err)
		}
		return nil
	})
	info("identity harness ready on %s (fake CAS, fixed TokenReview/Pod/Node table, test JWKS key)", url("identity"))

	profile := e.path("cfg", "control-health-profile.json")
	writeJSON(t, profile, map[string]any{
		"sources":         []map[string]string{{"source_id": "evidence-collector/receiver-primary", "san": top.pods["evidence-collector"].san(), "scope_id": "receiver-primary"}},
		"readers":         []string{top.pods["gateway"].san(), top.pods["coordinator"].san()},
		"guarded_profile": false, "audit_source_id": "control-health", "version": "m31-local", "environment": environment,
	})
	healthCfg := e.path("cfg", "control-health-harness.json")
	writeJSON(t, healthCfg, map[string]any{"listen": "127.0.0.1:" + ports["control-health"], "identity_url": url("identity"),
		"bootstrap_token": top.tokenFile(e, "control-health"), "tls_ca": ca, "profile": profile, "epoch_dir": epochDir(t, e, "control-health"),
		"nodes": map[string]string{top.NodeUID: top.BootID}})
	start(t, ps, e, "control-health", ports["control-health"], filepath.Join(e.bin, "control-health.test"), harnessArgs("TestM31LocalHealthHarness"),
		"M31_HEALTH_HARNESS_CONFIG="+healthCfg, "DATABASE_URL="+e.dsn(logins["control-health"]))

	sources := e.path("cfg", "audit-sources.json")
	writeJSON(t, sources, []map[string]any{{"source_id": tetragonSAN, "namespace": "agent-sensors", "ksa": "tetragon", "principal": "tetragon"}})
	start(t, ps, e, "audit-writer", ports["audit-writer"], filepath.Join(e.bin, "audit-writer"), []string{
		"--listen=127.0.0.1:" + ports["audit-writer"], "--identity-url=" + url("identity"), "--bootstrap-token=" + top.tokenFile(e, "audit-writer"),
		"--tls-ca=" + ca, "--sources=" + sources, "--health-url=" + url("control-health"), "--health-source-id=audit-writer",
		"--version=m31-local", "--work-events-gateway-san=" + top.pods["gateway"].san(),
		"--kernel", "--kernel-node-cidrs=127.0.0.1/32", "--lifecycle-epoch-dir=" + epochDir(t, e, "audit-writer"),
	}, "DATABASE_URL="+e.dsn(logins["audit-writer"]))

	kmsFake := startFakeKMS(t, e)
	ps.start(t, e, "audit-exporter", filepath.Join(e.bin, "audit-exporter"), []string{
		"--evidence-bucket=m31-audit-evidence", "--decision-bucket=m31-audit-decisions", "--kms-key-version=" + kmsFake.keyVersion,
		"--keys=" + e.path("cfg", "export-keys.json"), "--kms-endpoint=" + kmsFake.url, "--health-url=" + url("control-health"),
		"--health-source-id=audit-exporter", "--version=m31-local", "--instance-id=audit-exporter-0",
		"--identity-url=" + url("identity"), "--bootstrap-token=" + top.tokenFile(e, "audit-exporter"), "--tls-ca=" + ca,
	}, "DATABASE_URL="+e.dsn(logins["audit-exporter"]))

	brokerSecret := e.path("cfg", "broker-secret")
	writeFile(t, brokerSecret, []byte(base64.RawURLEncoding.EncodeToString(receiverKey)), 0o600)
	start(t, ps, e, "credential-broker", ports["credential-broker"], filepath.Join(e.bin, "broker.test"), harnessArgs("TestM31LocalBrokerHarness"),
		"M31_BROKER_HARNESS_LISTEN=127.0.0.1:"+ports["credential-broker"], "M31_BROKER_IDENTITY_URL="+url("identity"),
		"M31_BROKER_TOKEN_FILE="+top.tokenFile(e, "credential-broker"), "M31_BROKER_TLS_CA="+ca,
		"M31_BROKER_SECRET_NAME="+receiverSecret+"/versions/1", "M31_BROKER_SECRET_FILE="+brokerSecret,
		"DATABASE_URL="+e.dsn(logins["credential-broker"]))

	start(t, ps, e, "coordinator", ports["coordinator"], filepath.Join(e.bin, "coordinator"), []string{
		"--listen=127.0.0.1:" + ports["coordinator"], "--database-url=" + e.dsn(logins["coordinator"]), "--environment=" + environment,
		"--trust-bundle=" + ca, "--identity-url=" + url("identity"), "--bootstrap-token=" + top.tokenFile(e, "coordinator"),
		"--audit-source-id=coordinator", "--audit-source-version=m31-local", "--epoch-dir=" + epochDir(t, e, "coordinator"),
		"--health-url=" + url("control-health"), "--health-source-id=coordinator/coordinator-0",
	})
	start(t, ps, e, "gateway", ports["gateway"], filepath.Join(e.bin, "gateway"), []string{
		// 0.0.0.0: the runtime container reaches the gateway through host.docker.internal.
		"--listen=0.0.0.0:" + ports["gateway"], "--database-url=" + e.dsn(logins["gateway"]), "--environment=" + environment,
		"--gateway-san=" + top.pods["gateway"].san(), "--trust-bundle=" + ca, "--identity-url=" + url("identity"),
		"--bootstrap-token=" + top.tokenFile(e, "gateway"), "--bundle-key-id=prod-v1", "--bundle-key-file=" + bundleKey,
		"--adapter-urls=receiver-sender=" + url("receiver-sender"),
		"--model-profiles=" + filepath.Join(e.repo, "packages/canonical/testdata/model-profiles.json"),
		"--audit-source-id=policy-gateway", "--audit-source-version=m31-local", "--epoch-dir=" + epochDir(t, e, "gateway"),
		"--health-url=" + url("control-health"), "--health-source-id=gateway/gateway-0", "--audit-url=" + url("audit-writer"),
	})
	start(t, ps, e, "receiver", ports["receiver"], filepath.Join(e.bin, "receiver"), []string{
		"--listen=127.0.0.1:" + ports["receiver"], "--database-url=" + e.dsn(logins["receiver"]), "--receiver-mode=idempotent",
		"--target-id=receiver-primary", "--route-id=submissions-v1", "--trust-bundle=" + ca, "--identity-url=" + url("identity"),
		"--bootstrap-token=" + top.tokenFile(e, "receiver"), "--api-key-dir=" + keyDir,
	})
	ps.start(t, e, "evidence-collector", filepath.Join(e.bin, "evidence-collector"), []string{
		"--database-url=" + e.dsn(logins["evidence-collector"]), "--tenant=" + tenant, "--receiver-url=" + url("receiver"),
		"--target-id=receiver-primary", "--tls-ca=" + ca, "--identity-url=" + url("identity"),
		"--bootstrap-token=" + top.tokenFile(e, "evidence-collector"), "--health-url=" + url("control-health"),
		"--health-source-id=evidence-collector/receiver-primary", "--version=m31-local", "--audit-source-id=evidence-collector",
		"--audit-source-version=m31-local", "--epoch-dir=" + epochDir(t, e, "evidence-collector"), "--probe-action-key=" + uuid.NewString(),
	})

	step("6. Simulated node: node-sensors, lifecycle-recorder and node-readiness with their own workload certificates")
	sim := newNodeSim(t, e, top, db, url("identity"), url("control-health"), url("audit-writer"), imageDigest(t, e))
	if err := sim.renewLeases(); err != nil {
		t.Fatalf("first simulated leases: %v", err)
	}
	info("[API] leases: node-sensors (tetragon-node/%s, sensor_generation 1), lifecycle-recorder, node-readiness", top.NodeUID)
	sim.markNodeReady(t)
	go sim.run(ctx)

	step("7. Required leases before any session (adapter not started yet)")
	waitLeases(t, db, top, ps, []string{"audit-db", "audit-export", "gateway", "coordinator", "node-readiness", "destination-evidence", "node-sensors", "lifecycle-recorder"})
	requireNoHolds(t, db)
	if n := count(t, db, `SELECT count(*) FROM health.control_health_leases WHERE component='adapter'`); n != 0 {
		t.Fatalf("adapter lease exists before the adapter started: %d", n)
	}
	con := console{base: url("identity"), key: oidc, client: identityClient}

	step("8. Fail-closed (a): required adapter lease missing -> gateway denies, nothing dispatched")
	s1 := con.createSession(t, "M3-1 local e2e fail-closed case (a): adapter lease missing")
	info("session %s created by %s", s1.SessionID, consoleEmail)
	r1 := startRuntime(t, e, top, sim, "runtime-1", ports["gateway"], "3s")
	o1 := r1.wait(t, e, 3*time.Minute)
	r1.remove()
	sim.closeLifecycle(t, "runtime-1", r1.container)
	// The runtime sees 503 CONTROL_HEALTH_UNAVAILABLE (runbook step 8.4);
	// the stored decision is deny by health.required_leases.v1.
	if o1.ActionID == "" || !slices.Contains(o1.ReasonCodes, "CONTROL_HEALTH_UNAVAILABLE") {
		t.Fatalf("case (a): want CONTROL_HEALTH_UNAVAILABLE for the submitted action, got %s (action %q)", o1, o1.ActionID)
	}
	if n := count(t, db, `SELECT count(*) FROM audit.audit_events WHERE action_id=$1 AND event_type='policy_decided'
 AND safe_payload->>'verdict'='deny' AND safe_payload->'reason_codes' ? 'CONTROL_HEALTH_UNAVAILABLE'
 AND safe_payload->'matched_rule_ids' ? 'health.required_leases.v1'`, o1.ActionID); n != 1 {
		t.Fatalf("case (a): want one policy_decided deny by health.required_leases.v1, got %d", n)
	}
	requireNoDispatch(t, db, o1.ActionID)
	info("PASS case (a): action %s decided deny CONTROL_HEALTH_UNAVAILABLE (health.required_leases.v1), runtime got %v; no dispatch/attempt/receiver effect", o1.ActionID, o1.ReasonCodes)
	printAudit(t, db, "case (a) run "+o1.WorkRunID, o1.SessionID, o1.ActionID, o1.WorkRunID)

	step("9. Adapter (receiver-sender) start")
	// receiver-sender runs as its harness test binary: the real run() with a
	// fixed netns_inode (README "Simulated locally"; macOS has no /proc).
	senderArgs, err := json.Marshal([]string{
		"--listen=127.0.0.1:" + ports["receiver-sender"], "--identity-url=" + url("identity"), "--bootstrap-token=" + top.tokenFile(e, "receiver-sender"),
		"--tls-ca-file=" + ca, "--coordinator-url=" + url("coordinator"), "--broker-url=" + url("credential-broker"),
		"--stored-inputs=postgres", "--environment=" + environment, "--bundle-key-id=prod-v1", "--bundle-key-file=" + bundleKey,
		"--audit-source-id=receiver-sender", "--audit-source-version=m31-local", "--epoch-dir=" + epochDir(t, e, "receiver-sender"),
		"--health-url=" + url("control-health"), "--health-source-id=receiver-sender/receiver-sender-0",
	})
	if err != nil {
		t.Fatal(err)
	}
	start(t, ps, e, "receiver-sender", ports["receiver-sender"], filepath.Join(e.bin, "receiver-sender.test"),
		harnessArgs("TestM31LocalReceiverSenderHarness"), "M31_RECEIVER_SENDER_HARNESS_ARGS="+string(senderArgs),
		"M31_RECEIVER_SENDER_NETNS_INODE=4026531840",
		"DATABASE_URL="+e.dsn(logins["receiver-sender"]), "POD_UID="+top.pods["receiver-sender"].PodUID, "POD_NAME=receiver-sender-0")
	waitLeases(t, db, top, ps, []string{"adapter"})
	requireNoHolds(t, db)

	step("10. Main flow: session -> approval_required -> (b) no dispatch without approval -> approve -> dispatch")
	s2 := con.createSession(t, "M3-1 local e2e: submit one summary to receiver-primary")
	info("session %s created by %s", s2.SessionID, consoleEmail)
	r2 := startRuntime(t, e, top, sim, "runtime-2", ports["gateway"], "3s")
	defer r2.remove()
	var actionID string
	waitFor(t, "an action waiting for approval", 3*time.Minute, func() error {
		if p := con.pending(t, s2.SessionID); len(p) > 0 {
			actionID = p[0].ActionID
			return nil
		}
		return fmt.Errorf("none yet")
	})
	info("action %s is approval_required (pending for %s)", actionID, consoleEmail)
	// Wait for at least two :reevaluate cycles (3s approval poll) instead of a
	// fixed sleep, and check after every poll that nothing was dispatched.
	var reevals int
	waitFor(t, "two action_reevaluated events while unapproved", 90*time.Second, func() error {
		requireNoDispatch(t, db, actionID)
		reevals = count(t, db, `SELECT count(*) FROM audit.audit_events WHERE action_id=$1 AND event_type='action_reevaluated'`, actionID)
		if reevals < 2 {
			return fmt.Errorf("%d so far", reevals)
		}
		return nil
	})
	requireNoDispatch(t, db, actionID)
	info("PASS case (b): %d unapproved :reevaluate calls, no dispatch_enqueued/attempt/receiver effect", reevals)
	// decisions.action_content_previews shows content only for actions
	// evaluated at data class synthetic; a fresh workload is at none, and the
	// contract then fails closed (migration 20261016181826, SPEC-QUESTION).
	var dataClass string
	var previews int
	if err := db.QueryRow(bg(), `SELECT a.data_class::text, (SELECT count(*) FROM decisions.action_content_previews p WHERE p.content_digest = a.content_digest)
FROM decisions.actions a WHERE a.action_id = $1`, actionID).Scan(&dataClass, &previews); err != nil {
		t.Fatal(err)
	}
	if previews == 0 {
		status, raw := con.contractStatus(t, actionID)
		if status != 503 || !bytes.Contains(raw, []byte("STATE_STORE_UNAVAILABLE")) {
			t.Fatalf("action %s has no content preview (data_class %s), but the contract returned %d %s", actionID, dataClass, status, raw)
		}
		requireNoDispatch(t, db, actionID)
		info("approval contract for %s: %d %s (data_class %s, no row in decisions.action_content_previews); nothing dispatched", actionID, status, bytes.TrimSpace(raw), dataClass)
		var runID string
		_ = db.QueryRow(bg(), `SELECT coalesce(max(safe_payload->>'work_run_id'),'') FROM audit.audit_events WHERE session_id::text=$1`, s2.SessionID).Scan(&runID)
		printAudit(t, db, "main run "+runID+" (up to the approval contract)", s2.SessionID, actionID, runID)
		writeFile(t, result, []byte("blocked_preview\n"), 0o644)
		// A blocked run is not a pass for go test either (run-local.sh maps
		// the result file to exit 4).
		t.Errorf("BLOCKED at the approval contract: no content preview for action %s", actionID)
		return
	}
	_, ack := con.approve(t, actionID)
	info("approved: approval %v revision %v", ack["approval_id"], ack["revision"])
	o2 := r2.wait(t, e, 4*time.Minute)
	if o2.ActionID != actionID {
		t.Fatalf("runtime-2 reported action %q, approved %q", o2.ActionID, actionID)
	}
	if n := count(t, db, `SELECT count(*) FROM audit.audit_events WHERE action_id=$1 AND event_type='dispatch_enqueued'`, actionID); n != 1 {
		t.Fatalf("approved action: want 1 dispatch_enqueued, got %d (%s)", n, o2)
	}

	step("11. Adapter -> receiver send")
	tlsFailed := slices.Contains(o2.ReasonCodes, "TLS_VERIFY_FAILED") ||
		count(t, db, `SELECT count(*) FROM audit.audit_events WHERE action_id=$1 AND safe_payload::text LIKE '%TLS_VERIFY_FAILED%'`, actionID) > 0
	effects := count(t, db, `SELECT count(*) FROM receiver.receiver_effects WHERE action_key=$1`, actionID)
	if tlsFailed {
		if effects != 0 {
			t.Fatalf("TLS_VERIFY_FAILED but %d receiver effects for %s", effects, actionID)
		}
		time.Sleep(6 * time.Second) // one collector feed settle period
		if n := count(t, db, `SELECT count(*) FROM evidence.destination_observations WHERE action_id=$1 AND evidence_level IN ('accepted','effect_verified')`, actionID); n != 0 {
			t.Fatalf("TLS_VERIFY_FAILED but %d positive destination observations", n)
		}
		info("send failed closed with TLS_VERIFY_FAILED: 0 receiver effects, no receipt (%s)", o2)
		printAudit(t, db, "main run "+o2.WorkRunID+" (up to the failed send)", o2.SessionID, actionID, o2.WorkRunID)
		writeFile(t, result, []byte("blocked_tls\n"), 0o644)
		// A blocked run is not a pass for go test either (run-local.sh maps
		// the result file to exit 3).
		t.Errorf("BLOCKED at adapter -> receiver TLS: TLS_VERIFY_FAILED for action %s", actionID)
		return
	}
	// Gated stages: run only once the send itself succeeds.
	if o2.Verdict != "allow" || effects != 1 {
		t.Fatalf("send: want allow with one receiver effect, got %s and %d effects", o2, effects)
	}
	info("receiver accepted the X-Agentarium-Receiver-Key submission: 1 effect for action_key %s", actionID)

	step("12. Evidence-collector receipt")
	var level string
	var effectCount *int32
	waitFor(t, "destination observation", 60*time.Second, func() error {
		return db.QueryRow(bg(), `SELECT evidence_level, effect_count FROM evidence.destination_observations WHERE action_id=$1 ORDER BY revision DESC LIMIT 1`, actionID).Scan(&level, &effectCount)
	})
	if level != "effect_verified" || effectCount == nil || *effectCount != 1 {
		t.Fatalf("receipt: evidence_level %s effect_count %v", level, effectCount)
	}
	info("destination_observations: evidence_level=%s effect_count=%d", level, *effectCount)

	step("13. Audit query by session, action and work_run_id")
	if o2.WorkRunID == "" {
		t.Fatalf("runtime-2 reported no work_run_id (%s)", o2)
	}
	// Action-path events carry session_id and action_id; only the runtime's
	// agent_work_* and work_readiness_* events carry the work_run_id.
	if n := count(t, db, `SELECT count(*) FROM audit.audit_events WHERE safe_payload->>'work_run_id'=$1`, o2.WorkRunID); n == 0 {
		t.Fatalf("no audit event names work_run_id %s", o2.WorkRunID)
	}
	types := printAudit(t, db, "main run "+o2.WorkRunID, o2.SessionID, actionID, o2.WorkRunID)
	for _, want := range []string{"request_received", "policy_decided", "approval_requested", "approval_granted", "action_reevaluated",
		"dispatch_enqueued", "attempt_planned", "preflight_passed", "dispatch_started", "response_received", "destination_observed",
		"agent_work_start_requested", "agent_work_finished"} {
		if !slices.Contains(types, want) {
			t.Fatalf("audit trail of run %s lacks %s", o2.WorkRunID, want)
		}
	}
	writeFile(t, result, []byte("pass\n"), 0o644)
}

func harnessArgs(test string) []string {
	return []string{"-test.run", "^" + test + "$", "-test.v", "-test.timeout", "0"}
}

func epochDir(t *testing.T, e env, name string) string {
	t.Helper()
	d := e.path("epochs", name)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// start runs a listening service and waits for its port.
func start(t *testing.T, ps *procs, e env, name, port, bin string, args []string, extraEnv ...string) *proc {
	t.Helper()
	p := ps.start(t, e, name, bin, args, extraEnv...)
	waitFor(t, name+" listening on "+port, 60*time.Second, func() error {
		if !p.alive() {
			t.Fatalf("%s exited: %v\n%s", name, p.err, p.tail(40))
		}
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second)
		if err != nil {
			return err
		}
		return c.Close()
	})
	info("%s listening on 127.0.0.1:%s (log %s)", name, port, strings.TrimPrefix(p.log, e.work+"/"))
	return p
}

func createBucket(t *testing.T, name string) {
	t.Helper()
	c, err := storage.NewClient(bg())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bucket(name).Create(bg(), "m31-local", nil); err != nil {
		t.Fatalf("bucket %s: %v", name, err)
	}
	info("bucket gs://%s (emulator %s)", name, os.Getenv("STORAGE_EMULATOR_HOST"))
}

// renderCatalog renders catalog/gcp like the installer does from the lock,
// with local values: receiver-primary's origin is the local receiver
// (expected_tls_name unchanged), its allowed CIDR 127.0.0.1/32, and every
// other placeholder a dummy value of the right shape.
func renderCatalog(t *testing.T, e env, receiverPort string) string {
	t.Helper()
	dir := e.path("catalog")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ops, err := os.ReadFile(filepath.Join(e.repo, "catalog/gcp/operations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "operations.yaml"), ops, 0o600)
	raw, err := os.ReadFile(filepath.Join(e.repo, "catalog/gcp/targets.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	target := ""
	for _, line := range strings.Split(string(raw), "\n") {
		trim := strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(trim, "- target_id: "); ok {
			target = strings.Fields(v)[0]
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
		switch {
		case target == "receiver-primary" && strings.HasPrefix(trim, "origin:"):
			line = indent + "origin: https://localhost:" + receiverPort
		case strings.HasPrefix(trim, "allowed_cidrs:") && strings.Contains(trim, "<"):
			cidr := map[string]string{"k8s-agent-targets": "10.96.0.1/32", "receiver-primary": "127.0.0.1/32", "receiver-probe": "10.96.0.11/32",
				"evidence-api": "10.96.0.12/32", "discovery-snapshots": "10.96.0.13/32"}[target]
			if cidr == "" {
				t.Fatalf("no local CIDR for target %s", target)
			}
			line = indent + `allowed_cidrs: ["` + cidr + `"]`
		default:
			line = strings.NewReplacer("<location>", "us-central1", "<PROJECT_ID>", "m31-local", "<LOCATION>", "us-central1", "<MODEL_ID>", "m31-local-model").Replace(line)
		}
		if strings.Contains(strings.SplitN(line, "#", 2)[0], "<") {
			t.Fatalf("unrendered placeholder: %s", line)
		}
		out = append(out, line)
	}
	writeFile(t, filepath.Join(dir, "targets.yaml"), []byte(strings.Join(out, "\n")), 0o600)
	info("catalog rendered to %s: receiver-primary origin https://localhost:%s, expected_tls_name receiver.agent-targets.svc, allowed_cidrs 127.0.0.1/32", dir, receiverPort)
	return dir
}

type bundleResult struct {
	BundleID        string `json:"bundle_id"`
	Revision        string `json:"revision"`
	CandidateDigest string `json:"candidate_digest"`
	ArtifactDigest  string `json:"artifact_digest"`
	CatalogDigest   string `json:"catalog_digest"`
	ObjectURI       string `json:"object_uri"`
	changeID        string
}

func publishBundle(t *testing.T, e env, catalogDir string) bundleResult {
	t.Helper()
	res := bundleResult{changeID: uuid.NewString()}
	// No production policy data exists yet (#30); the decision.rego test data
	// is used without its "_comment" key, which the bundle builder rejects.
	var data map[string]json.RawMessage
	raw, err := os.ReadFile(filepath.Join(e.repo, "policies/gateway/testdata/policy-data.json"))
	if err != nil || json.Unmarshal(raw, &data) != nil {
		t.Fatalf("policy data: %v", err)
	}
	delete(data, "_comment")
	// The test data has no adapter_constraints, and receiver-sender rejects
	// every action at preflight without its entry (COMMON appendix A). The route
	// is the receiver.submit catalog route; the response bound is its
	// response_limit_bytes.
	var constraints map[string]json.RawMessage
	if err := json.Unmarshal(data["adapter_constraints"], &constraints); err != nil || constraints == nil {
		constraints = map[string]json.RawMessage{}
	}
	constraints["receiver-sender"] = json.RawMessage(`{"max_request_bytes": 65536, "max_response_bytes": 65536, "allowed_route_ids": ["submissions-v1"]}`)
	if data["adapter_constraints"], err = json.Marshal(constraints); err != nil {
		t.Fatal(err)
	}
	policyData := e.path("cfg", "policy-data.json")
	writeJSON(t, policyData, data)
	// The policy directory holds only the Rego modules (no Go tests, no data).
	policyDir := e.path("policy")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	modules, _ := filepath.Glob(filepath.Join(e.repo, "policies/gateway/*.rego"))
	for _, m := range modules {
		if strings.HasSuffix(m, "_test.rego") {
			continue
		}
		raw, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(policyDir, filepath.Base(m)), raw, 0o600)
	}
	out := e.path("cfg", "bundle-result.json")
	cmd := exec.Command(filepath.Join(e.bin, "first-bundle.test"), harnessArgs("TestM31LocalBundleHarness")...)
	cmd.Dir = filepath.Join(e.repo, "tools/first-bundle")
	cmd.Env = append(baseEnv(e), "M31_BUNDLE_HARNESS=1", "M31_BUNDLE_POLICY_DIR="+policyDir,
		"M31_BUNDLE_CATALOG_DIR="+catalogDir, "M31_BUNDLE_POLICY_DATA="+policyData,
		"M31_BUNDLE_REVISION=m31-local-1", "M31_BUNDLE_PUBLIC_KEY_FILE="+e.path("cfg", "bundle-prod-v1.pem"), "M31_BUNDLE_ID=m3-1-local",
		"M31_BUNDLE_BUCKET=m31-bundles", "M31_BUNDLE_ENVIRONMENT="+environment, "M31_BUNDLE_CHANGE_ID="+res.changeID,
		"M31_BUNDLE_RESULT_FILE="+out, "DATABASE_URL="+e.dsn("postgres"))
	b, err := cmd.CombinedOutput()
	_ = os.WriteFile(e.path("logs", "first-bundle.log"), b, 0o600)
	if err != nil {
		t.Fatalf("bundle harness: %v (log %s):\n%s", err, e.path("logs", "first-bundle.log"), strings.ReplaceAll(string(b), "\n", "\n   | "))
	}
	raw, err = os.ReadFile(out)
	if err != nil || json.Unmarshal(raw, &res) != nil || res.ArtifactDigest == "" {
		t.Fatalf("bundle result: %v %s", err, raw)
	}
	info("bundle %s revision %s artifact %s published to %s; release.desired_bundle written", res.BundleID, res.Revision, res.ArtifactDigest[:16], res.ObjectURI)
	return res
}

// imageDigest is the runtime image's manifest digest as a node witness
// reads it from the container runtime.
func imageDigest(t *testing.T, e env) string {
	t.Helper()
	out, err := exec.Command("docker", "image", "inspect", "-f", "{{index .RepoDigests 0}}", e.runtimeImage).Output()
	if err != nil {
		t.Fatalf("runtime image digest: %v", err)
	}
	_, d, ok := strings.Cut(strings.TrimSpace(string(out)), "@")
	if !ok {
		t.Fatalf("runtime image %s has no repo digest", e.runtimeImage)
	}
	return d
}

// waitLeases waits until every listed component has an unexpired healthy
// lease on the scope the gateway/coordinator read. The coordinator accepts a
// degraded lease (TASK-03 3.2 reads lease_until only), but a healthy setup is
// required here: the gateway's first report precedes its first bundle load
// and is degraded until the next 5s heartbeat.
func waitLeases(t *testing.T, db *pgxpool.Pool, top topology, ps *procs, components []string) {
	t.Helper()
	waitFor(t, "required leases "+strings.Join(components, ","), 90*time.Second, func() error {
		for _, p := range ps.list {
			if !p.alive() {
				t.Fatalf("%s exited: %v\n%s", p.name, p.err, p.tail(40))
			}
		}
		var missing []string
		for _, c := range components {
			n := count(t, db, `SELECT count(*) FROM health.control_health_leases WHERE component=$1 AND lease_until>now() AND observed_state='healthy'`, c)
			if n == 0 {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("missing %v", missing)
		}
		return nil
	})
	rows, err := db.Query(bg(), `SELECT component, scope, scope_id, source_id, observed_state, coalesce(active_version,''), coalesce(loaded_artifact_digest,'')
FROM health.control_health_leases WHERE component = ANY($1) AND lease_until>now() ORDER BY component`, components)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var c, scope, id, src, state, av, la string
		if err := rows.Scan(&c, &scope, &id, &src, &state, &av, &la); err != nil {
			t.Fatal(err)
		}
		v := av
		if la != "" {
			v = "artifact " + la[:16]
		} else if len(v) > 24 {
			v = v[:24]
		}
		info("lease %-20s %-8s %-38s %-44s %s %s", c, scope, id, src, state, v)
	}
}

func requireNoHolds(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	rows, err := db.Query(bg(), `SELECT scope, scope_id, reason, owner_component FROM health.holds WHERE released_at IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var open []string
	for rows.Next() {
		var a, b, c, d string
		_ = rows.Scan(&a, &b, &c, &d)
		open = append(open, a+"/"+b+" "+c+" ("+d+")")
	}
	if len(open) > 0 {
		t.Fatalf("open holds: %v", open)
	}
	info("no open holds")
}

// requireNoDispatch checks that nothing past the decision happened for the
// action: no dispatch, no coordinator attempt, no adapter call, no receiver
// effect.
func requireNoDispatch(t *testing.T, db *pgxpool.Pool, actionID string) {
	t.Helper()
	n := count(t, db, `SELECT count(*) FROM audit.audit_events WHERE action_id=$1 AND event_type IN
 ('dispatch_enqueued','attempt_planned','preflight_passed','dispatch_started','response_received','attempt_uncertain','attempt_failed','destination_observed')`, actionID)
	effects := count(t, db, `SELECT count(*) FROM receiver.receiver_effects WHERE action_key=$1`, actionID)
	if n != 0 || effects != 0 {
		t.Fatalf("action %s: %d dispatch/attempt audit events, %d receiver effects; want none", actionID, n, effects)
	}
}

// printAudit prints every event of the run's session, its action, or naming
// the work_run_id (the action path carries session_id and action_id; the
// runtime's work events carry the work_run_id). It returns the event types.
func printAudit(t *testing.T, db *pgxpool.Pool, title, sessionID, actionID, runID string) []string {
	t.Helper()
	info("audit events of %s (session %s, action %s):", title, sessionID, actionID)
	rows, err := db.Query(bg(), `SELECT event_type, source_id, received_at, coalesce(safe_payload->'reason_codes','[]'::jsonb)::text
FROM audit.audit_events
WHERE ($1<>'' AND session_id::text=$1) OR ($2<>'' AND action_id::text=$2) OR ($3<>'' AND safe_payload->>'work_run_id'=$3)
ORDER BY received_at, event_id`, sessionID, actionID, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var types []string
	for rows.Next() {
		var et, src, reasons string
		var at time.Time
		if err := rows.Scan(&et, &src, &at, &reasons); err != nil {
			t.Fatal(err)
		}
		types = append(types, et)
		if len(src) > 60 {
			src = "..." + src[len(src)-57:]
		}
		if reasons == "[]" {
			reasons = ""
		}
		fmt.Printf("     %s  %-28s %-60s %s\n", at.UTC().Format("15:04:05.000"), et, src, reasons)
	}
	if len(types) == 0 {
		t.Fatalf("no audit events for %s", title)
	}
	return types
}
