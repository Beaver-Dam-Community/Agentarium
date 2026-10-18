//go:build integration

package receipt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Runs the existing receiver binary against real PostgreSQL; no replacement
// receiver Handler or Store is used. Requires an explicitly disposable cluster.
func TestReceiverPostgres(t *testing.T) {
	dsn := os.Getenv("EVIDENCE_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable EVIDENCE_TEST_ADMIN_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	db, login := "receiptdb_"+suffix, "receiptlogin_"+suffix
	run := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	var passwordBytes [32]byte
	if _, err := rand.Read(passwordBytes[:]); err != nil {
		t.Fatal(err)
	}
	// Generated hex has no SQL quoting characters and is never logged. Use a
	// distinct runtime password so password-authenticated PostgreSQL is tested.
	password := hex.EncodeToString(passwordBytes[:])
	run(admin, "CREATE ROLE "+login+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '"+password+"'")
	run(admin, "CREATE DATABASE "+db)
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+db+" WITH (FORCE)")
		if _, err := admin.Exec(context.Background(), "DROP ROLE "+login); err != nil {
			t.Error(err)
		}
	}()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = db
	install, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer install.Close(context.Background())
	sql, err := os.ReadFile("../../../../migrations/20261015151000_receiver_effects.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	run(install, string(sql))
	run(admin, "GRANT receiver_writer,receipt_reader TO "+login)
	runtimeURL, err := url.Parse(dsn)
	if err != nil || (runtimeURL.Scheme != "postgres" && runtimeURL.Scheme != "postgresql") {
		t.Fatal("fixture requires a PostgreSQL URL")
	}
	runtimeURL.Path = "/" + db
	runtimeURL.User = url.UserPassword(login, password)
	runtimeCfg := cfg.Copy()
	runtimeCfg.User = login
	runtimeCfg.Password = password
	restricted, err := pgx.ConnectConfig(ctx, runtimeCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restricted.Close(context.Background())
	var elevated bool
	if err = restricted.QueryRow(ctx, "SELECT rolsuper OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname=current_user").Scan(&elevated); err != nil || elevated {
		t.Fatal("runtime unexpectedly privileged", err)
	}
	binary := filepath.Join(t.TempDir(), "receiver")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "../../../../services/receiver/cmd/receiver")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build receiver %s: %v", out, err)
	}
	ca := testCA(t)
	serverCert, serverKey, _ := ca.leaf(t, "receiver", ReceiverSAN, x509.ExtKeyUsageServerAuth)
	cp, kp, _ := ca.leaf(t, "collector", CollectorSAN, x509.ExtKeyUsageClientAuth)
	_, _, senderCert := ca.leaf(t, "sender", "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender", x509.ExtKeyUsageClientAuth)
	// One active receiver API key version (--api-key-dir contract).
	keyDir := t.TempDir()
	receiverKey := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	if err := os.WriteFile(filepath.Join(keyDir, "1"), []byte(receiverKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A missing, empty or invalid key directory stops the receiver at start.
	badDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(badDir, "latest"), []byte(receiverKey), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dirArgs := range [][]string{nil, {"--api-key-dir", t.TempDir()}, {"--api-key-dir", badDir}} {
		args := append([]string{"--listen", "127.0.0.1:0", "--receiver-mode", "idempotent", "--target-id", "receiver-primary", "--trust-bundle", ca.ca, "--tls-cert", serverCert, "--tls-key", serverKey}, dirArgs...)
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = append(os.Environ(), "RECEIVER_DATABASE_URL="+runtimeURL.String())
		if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "receiver stopped") {
			t.Fatalf("receiver started with key dir args %v: %s %v", dirArgs, out, err)
		}
	}
	for _, mode := range []string{"idempotent", "non_idempotent"} {
		t.Run(mode, func(t *testing.T) {
			// Reserve a loopback address immediately before spawning the actual binary.
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := l.Addr().String()
			_ = l.Close()
			processCtx, stop := context.WithCancel(ctx)
			defer stop()
			cmd := exec.CommandContext(processCtx, binary, "--listen", addr, "--receiver-mode", mode, "--target-id", "receiver-primary", "--route-id", "submissions-v1", "--target-version", "integration-v1", "--trust-bundle", ca.ca, "--tls-cert", serverCert, "--tls-key", serverKey, "--api-key-dir", keyDir)
			cmd.Env = append(os.Environ(), "RECEIVER_DATABASE_URL="+runtimeURL.String())
			var logs bytes.Buffer
			cmd.Stdout = &logs
			cmd.Stderr = &logs
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { stop(); _ = cmd.Wait() }()
			collector, err := NewClient("https://"+addr, cp, kp, ca.ca)
			if err != nil {
				t.Fatal(err)
			}
			// Reuse only the production client's server verifier for the sender test;
			// change its client certificate to the existing receiver-sender identity.
			transport := collector.http.Transport.(*http.Transport).Clone()
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
			transport.TLSClientConfig.GetClientCertificate = nil
			transport.TLSClientConfig.Certificates = []tls.Certificate{senderCert}
			sender := &http.Client{Transport: transport, Timeout: 4 * time.Second}
			action := uuid.NewString()
			body := []byte(`{"email":null,"summary":"receipt test"}`)
			sum := sha256.Sum256(body)
			want := Expected{ActionID: action, TargetID: "receiver-primary", RouteID: "submissions-v1", WireBodyDigest: hex.EncodeToString(sum[:])}
			var result Result
			for i := 0; i < 100; i++ {
				result, err = collector.Check(ctx, want)
				if err == nil {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(30 * time.Millisecond):
				}
			}
			if err != nil {
				t.Fatal("receiver did not become ready", err)
			}
			if result.RuleID != "R5" || result.EvidenceLevel != "unknown" {
				t.Fatal("empty receipt asserted non-send", result)
			}
			want.AttemptFailed = true
			result, err = collector.Check(ctx, want)
			if err != nil || result.RuleID != "R6" {
				t.Fatal("failed-before-send empty receipt", result, err)
			}
			// The receiver key is checked before any DB write: missing and wrong
			// keys are 401 RECEIVER_KEY_INVALID and leave no attempt row.
			for _, k := range []string{"", "BBECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"} {
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/test/v1/submissions", bytes.NewReader([]byte(`{"email":null,"summary":"receipt test"}`)))
				req.Header.Set("Idempotency-Key", action)
				req.Header.Set("X-Agentarium-Attempt-Id", uuid.NewString())
				if k != "" {
					req.Header.Set("X-Agentarium-Receiver-Key", k)
				}
				resp, err := sender.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(b), "RECEIVER_KEY_INVALID") {
					t.Fatalf("receiver key %q: %d %s", k, resp.StatusCode, b)
				}
			}
			var rejected int
			if err := install.QueryRow(ctx, `SELECT count(*) FROM receiver.receiver_attempts WHERE action_key=$1`, action).Scan(&rejected); err != nil || rejected != 0 {
				t.Fatal("rejected receiver key left attempt rows", rejected, err)
			}
			submit := func(payload []byte, expectedStatus int) {
				t.Helper()
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/test/v1/submissions", bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Idempotency-Key", action)
				req.Header.Set("X-Agentarium-Attempt-Id", uuid.NewString())
				req.Header.Set("X-Agentarium-Receiver-Key", receiverKey)
				resp, err := sender.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != expectedStatus {
					t.Fatalf("submit %d %s", resp.StatusCode, b)
				}
			}
			submit(body, http.StatusCreated)
			result, err = collector.Check(ctx, want)
			if err != nil || result.RuleID != "R1" || result.Receipt.EffectCount != 1 {
				t.Fatal("real effect not verified", result, err)
			}
			// An independently committed effect overrides earlier attempt_failed input.
			if !want.AttemptFailed || result.EvidenceLevel != "effect_verified" {
				t.Fatal("attempt failure overrode receipt")
			}
			retryStatus := http.StatusOK
			if mode == "non_idempotent" {
				retryStatus = http.StatusCreated
			}
			submit(body, retryStatus)
			result, err = collector.Check(ctx, want)
			if err != nil {
				t.Fatal(err)
			}
			expectedEffects := 1
			expectedRule := "R1"
			if mode == "non_idempotent" {
				expectedEffects = 2
				expectedRule = "R2"
			}
			if result.RuleID != expectedRule || result.Receipt.EffectCount != expectedEffects || len(result.Receipt.ReceiverAttempts) != 2 {
				t.Fatalf("dedupe/effects conflated: %+v", result)
			}
			var dbEffects, dbAttempts int
			runQuery := `SELECT (SELECT count(*) FROM receiver.receiver_effects WHERE action_key=$1),(SELECT count(*) FROM receiver.receiver_attempts WHERE action_key=$1)`
			if err := install.QueryRow(ctx, runQuery, action).Scan(&dbEffects, &dbAttempts); err != nil || dbEffects != expectedEffects || dbAttempts != 2 {
				t.Fatal("independent DB rows disagree", err)
			}
			// A correct committed effect cannot hide a changed-body retry.
			mutatedStatus := http.StatusCreated
			if mode == "idempotent" {
				mutatedStatus = http.StatusConflict
			}
			submit([]byte(`{"email":null,"summary":"mutated receipt test"}`), mutatedStatus)
			result, err = collector.Check(ctx, want)
			if mode == "non_idempotent" {
				expectedEffects++
			}
			if err != nil || result.RuleID != "R2" || result.EvidenceLevel != "effect_mismatch" || result.Receipt.EffectCount != expectedEffects || len(result.Receipt.ReceiverAttempts) != 3 {
				t.Fatal("mutated retry hidden by committed effect", result, err)
			}
			if err := install.QueryRow(ctx, runQuery, action).Scan(&dbEffects, &dbAttempts); err != nil || dbEffects != expectedEffects || dbAttempts != 3 {
				t.Fatal("mutated retry DB rows disagree", err)
			}
			// The sender remains prohibited from reading the independent receipt.
			resp, err := sender.Get("https://" + addr + "/test/v1/receipts/" + action)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatal("adapter read receipt", resp.StatusCode)
			}
			// Verify full receipt digest against the receiver's own raw wire response.
			resp, err = collector.http.Get("https://" + addr + "/test/v1/receipts/" + action)
			if err != nil {
				t.Fatal(err)
			}
			wire, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var shape map[string]json.RawMessage
			if err = json.Unmarshal(wire, &shape); err != nil || len(shape) != 8 {
				t.Fatal("wire shape changed", err)
			}
			_, digest, err := decode(wire)
			if err != nil || digest != result.ReceiptDigest {
				t.Fatal("receipt digest drift", err)
			}
		})
	}
}
