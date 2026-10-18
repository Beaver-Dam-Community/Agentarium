//go:build integration

package m31

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

// console is the operator console: a Google ID token (signed by the local
// OIDC key) on the identity session and approval APIs.
type console struct {
	base   string
	key    oidcKey
	client *http.Client
}

// sanClient verifies the server chain against the local CA and the exact URI
// SAN, as every Agentarium client does (the certificates carry no DNS name
// for hostname verification). cert, when set, is presented for mTLS.
func sanClient(t *testing.T, caFile, san string, cert func() (*tls.Certificate, error)) *http.Client {
	t.Helper()
	raw, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		t.Fatal("ca bundle has no certificate")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			leaf := cs.PeerCertificates[0]
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return err
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != san {
				return fmt.Errorf("server SAN %v, want %s", leaf.URIs, san)
			}
			return nil
		}}
	if cert != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert() }
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
}

// call sends a JSON request and decodes a JSON response into out. It returns
// the status and the raw body.
func call(c *http.Client, method, u, bearer string, body, out any) (int, []byte, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, r)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if out != nil && resp.StatusCode/100 == 2 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, raw, err
		}
	}
	return resp.StatusCode, raw, nil
}

type sessionCreated struct {
	SessionID      string    `json:"session_id"`
	ClaimExpiresAt time.Time `json:"claim_expires_at"`
}

// createSession is the console POST /v1/sessions for one receiver.submit
// to receiver-primary by the agent-exec/agent-runtime workload.
func (c console) createSession(t *testing.T, task string) sessionCreated {
	t.Helper()
	var out sessionCreated
	status, raw, err := call(c.client, "POST", c.base+"/v1/sessions", c.key.idToken(t), map[string]any{
		"workload_id": "agent-exec/agent-runtime", "task_statement": task,
		"requested_scope": map[string]any{"operation_ids": []string{"receiver.submit"}, "target_ids": []string{"receiver-primary"}},
	}, &out)
	if err != nil || status/100 != 2 || out.SessionID == "" {
		t.Fatalf("create session: %d %v %s", status, err, raw)
	}
	return out
}

type pendingAction struct {
	ActionID string `json:"action_id"`
}

// pending lists the session's actions waiting for this approver.
func (c console) pending(t *testing.T, sessionID string) []pendingAction {
	t.Helper()
	var out struct {
		Actions []pendingAction `json:"actions"`
	}
	status, raw, err := call(c.client, "GET", c.base+"/v1/approvals/pending?session_id="+url.QueryEscape(sessionID), c.key.idToken(t), nil, &out)
	if err != nil || status != 200 {
		t.Fatalf("pending approvals: %d %v %s", status, err, raw)
	}
	return out.Actions
}

type approvalContract struct {
	ContractDigest string          `json:"contract_digest"`
	Nonce          string          `json:"nonce"`
	Contract       json.RawMessage `json:"contract"`
	IntentCheck    json.RawMessage `json:"intent_check"`
}

// contractStatus is one GET of the approval contract: its status and body.
func (c console) contractStatus(t *testing.T, actionID string) (int, []byte) {
	t.Helper()
	status, raw, err := call(c.client, "GET", c.base+"/v1/actions/"+actionID+"/approval-contract", c.key.idToken(t), nil, nil)
	if err != nil {
		t.Fatalf("approval contract: %v", err)
	}
	return status, raw
}

// approve renders the approval contract and approves it with the shown
// digest and nonce (COMMON approval flow).
func (c console) approve(t *testing.T, actionID string) (approvalContract, map[string]any) {
	t.Helper()
	var ct approvalContract
	status, raw, err := call(c.client, "GET", c.base+"/v1/actions/"+actionID+"/approval-contract", c.key.idToken(t), nil, &ct)
	if err != nil || status != 200 || ct.ContractDigest == "" || ct.Nonce == "" {
		t.Fatalf("approval contract: %d %v %s", status, err, raw)
	}
	var out map[string]any
	status, raw, err = call(c.client, "POST", c.base+"/v1/approvals", c.key.idToken(t), map[string]any{
		"action_id": actionID, "displayed_contract_digest": ct.ContractDigest, "nonce": ct.Nonce, "acknowledged_findings": []string{},
	}, &out)
	if err != nil || status/100 != 2 {
		t.Fatalf("approve: %d %v %s", status, err, raw)
	}
	return ct, out
}
