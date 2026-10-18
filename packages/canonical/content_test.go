package canonical

import "testing"

func strp(s string) *string { return &s }

func TestCheckReceiverContent(t *testing.T) {
	cat := testCatalog(t)
	op := cat.Operations[OpReceiverSubmit]
	cases := []struct {
		summary string
		denied  bool
	}{
		{"3 pods restarted", false},
		{"contact alice@example.com", true},
		{"ALICE.B+tag@Sub.Example.CO", true},
		{"x@y.z", false},                    // TLD shorter than 2 letters
		{"alice at example dot com", false}, // obfuscation is not claimed to be detected
		{"alice@example", false},
		{"user SYN-USER-0001 restarted", true},
		{"user syn-user-0001 restarted", false}, // identifiers match case-sensitively
		{"SYN-USER-0003", false},
	}
	for _, c := range cases {
		err := CheckReceiverContent(op, ReceiverPayload{Summary: c.summary})
		if c.denied != (err != nil) {
			t.Errorf("%q: denied=%v err=%v", c.summary, c.denied, err)
		}
		if err != nil && (err.HTTPStatus != 403 || err.ReasonCodes[0] != ReasonContentPatternDenied || err.RuleID != RuleContentPattern) {
			t.Errorf("%q: wrong error %v", c.summary, err)
		}
	}
	// The email field itself is not checked when fields = [summary].
	if err := CheckReceiverContent(op, ReceiverPayload{Summary: "ok", Email: strp("bob@example.com")}); err != nil {
		t.Errorf("email field checked: %v", err)
	}
	// fields may include email.
	both := []string{"summary", "email"}
	op2 := op
	cc := *op.ContentChecks
	cc.Fields = &both
	op2.ContentChecks = &cc
	if err := CheckReceiverContent(op2, ReceiverPayload{Summary: "ok", Email: strp("bob@example.com")}); err == nil {
		t.Error("email field not checked when listed")
	}
	// Absent fields defaults to summary.
	cc3 := *op.ContentChecks
	cc3.Fields = nil
	op3 := op
	op3.ContentChecks = &cc3
	if err := CheckReceiverContent(op3, ReceiverPayload{Summary: "a@b.cd"}); err == nil {
		t.Error("default fields did not check summary")
	}
	// Unknown field name fails closed.
	bad := []string{"phone"}
	cc4 := *op.ContentChecks
	cc4.Fields = &bad
	op4 := op
	op4.ContentChecks = &cc4
	if err := CheckReceiverContent(op4, ReceiverPayload{Summary: "ok"}); err == nil || err.ReasonCodes[0] != ReasonEndpointNotRegistered {
		t.Errorf("unknown field: %v", err)
	}
	// No content_checks: nothing is checked.
	op5 := op
	op5.ContentChecks = nil
	if err := CheckReceiverContent(op5, ReceiverPayload{Summary: "a@b.cd"}); err != nil {
		t.Errorf("no content_checks: %v", err)
	}
}

// Section 7 "content checker": a synthetic email in the allowed summary field is
// denied by Normalize with 403 and no envelope.
func TestNormalizeContentPatternDenied(t *testing.T) {
	cat := testCatalog(t)
	env, content, err := NormalizeRaw(body(OpReceiverSubmit, `{"target_id":"receiver-primary"}`, `{"payload":{"summary":"mail alice@example.com","email":null}}`), testTrusted(), cat)
	if err == nil || err.HTTPStatus != 403 || err.ReasonCodes[0] != ReasonContentPatternDenied || err.RuleID != RuleContentPattern {
		t.Fatalf("got %v", err)
	}
	if env.ActionDigest != "" || content.ContentBytes != nil {
		t.Fatal("no envelope or content may be produced on denial")
	}
}
