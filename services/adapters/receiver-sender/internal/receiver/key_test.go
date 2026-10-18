package receiver_test

import (
	"bytes"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/services/adapters/receiver-sender/internal/receiver"
)

func TestValidKey(t *testing.T) {
	for v, ok := range map[string]bool{
		apiKeyValue:                   true,
		strings.Repeat("A", 43):       true, // 32 zero bytes
		strings.Repeat("A", 42):       false,
		strings.Repeat("A", 44):       false,
		apiKeyValue[:42] + "=":        false, // padding
		apiKeyValue[:42] + "+":        false, // standard alphabet
		apiKeyValue[:42] + "B":        false, // non-zero trailing bits (Strict)
		" " + apiKeyValue[1:]:         false,
		"":                            false,
		strings.Repeat("_", 42) + "w": true,
		"synthetic-key-123":           false,
		apiKeyValue[:21] + "\n" + apiKeyValue[22:]: false,
	} {
		if receiver.ValidKey(v) != ok {
			t.Errorf("ValidKey(%q) = %v", v, !ok)
		}
	}
}

func TestCheckCredential(t *testing.T) {
	good := execute.Credential{SecretVersion: "3", HeaderName: receiver.KeyHeader, HeaderValue: apiKeyValue, ExpiresAt: time.Now().Add(time.Minute)}
	if err := (receiver.Adapter{}).CheckCredential("receiver-api-key", good); err != nil {
		t.Fatal(err)
	}
	lower := good
	lower.HeaderName = "x-agentarium-receiver-key"
	if err := (receiver.Adapter{}).CheckCredential("receiver-api-key", lower); err != nil {
		t.Fatalf("header names are case-insensitive: %v", err)
	}
	for name, mut := range map[string]func(*execute.Credential, *string){
		"other binding": func(_ *execute.Credential, b *string) { *b = "model-token" },
		"bearer header": func(c *execute.Credential, _ *string) {
			c.HeaderName, c.HeaderValue = "Authorization", "Bearer "+apiKeyValue
		},
		"other header": func(c *execute.Credential, _ *string) { c.HeaderName = "X-Receiver-Api-Key" },
		"short value":  func(c *execute.Credential, _ *string) { c.HeaderValue = "synthetic-key-123" },
	} {
		c, b := good, "receiver-api-key"
		mut(&c, &b)
		err := (receiver.Adapter{}).CheckCredential(b, c)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), apiKeyValue) || strings.Contains(err.Error(), c.HeaderValue) {
			t.Errorf("%s: error carries the value: %v", name, err)
		}
	}
}

// The broker answers without the receiver key header (a binding with
// another header_name): the adapter releases before the claim and sends
// nothing, rather than letting the receiver answer 401.
func TestReceiverKeyAbsentReleasesBeforeClaim(t *testing.T) {
	h := newHarness(t)
	h.broker.header, h.broker.value = "Authorization", "Bearer "+apiKeyValue
	d, a := h.action(okPayload)
	row := h.run(d, a)
	if row.State != execute.StateFailed || h.recv.count.Load() != 0 {
		t.Fatalf("state %s sends %d", row.State, h.recv.count.Load())
	}
	o := h.coord.last()
	if o.Transition != "released" || !slices.Equal(o.ReasonCodes, []string{"CREDENTIAL_UNAVAILABLE"}) {
		t.Fatalf("outcome %+v", o)
	}
	if slices.Contains(h.log.list(), "claim") {
		t.Fatal("permit claimed without a receiver key")
	}
}

// A well-formed key the receiver does not accept (rotated out, wrong
// secret): the receiver answers 401 RECEIVER_KEY_INVALID. That is a received
// response: execution failed with TARGET_REJECTED, one send, no retry, and
// the key appears in no log line or audit event.
func TestReceiverKeyRejectedIsOneFailedAttempt(t *testing.T) {
	h := newHarness(t)
	var logs bytes.Buffer
	h.cfg.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.useStore(h.store)
	h.broker.value = strings.Repeat("A", 43)
	d, a := h.action(okPayload)
	row := h.run(d, a)
	// The adapter row completes (the commit order ran); the ActionResult says failed.
	if row.State != execute.StateCompleted || h.recv.count.Load() != 1 || h.coord.reservations != 1 {
		t.Fatalf("state %s sends %d reservations %d", row.State, h.recv.count.Load(), h.coord.reservations)
	}
	if got := h.recv.headers[0].Get(receiver.KeyHeader); got != strings.Repeat("A", 43) {
		t.Fatal("receiver key header not sent")
	}
	o := h.coord.last()
	if o.Transition != "response_received" || !slices.Equal(o.ReasonCodes, []string{"TARGET_REJECTED"}) {
		t.Fatalf("outcome %+v", o)
	}
	r := h.store.results[row.AttemptID]
	if r.ExecutionState != "failed" || r.EvidenceLevel != "none" {
		t.Fatalf("result %+v", r)
	}
	if ev := h.audit.find("response_received"); ev == nil || ev.Payload["status_code"] != 401 {
		t.Fatalf("response_received %+v", ev)
	}
	// Restart: the attempt is finished; nothing is sent again.
	if err := h.engine.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h.recv.count.Load() != 1 {
		t.Fatal("a rejected attempt was sent again")
	}
	for _, k := range []string{strings.Repeat("A", 43), apiKeyValue} {
		if strings.Contains(logs.String(), k) {
			t.Fatal("receiver key in the adapter log")
		}
	}
}
