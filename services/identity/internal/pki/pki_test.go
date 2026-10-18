package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net/url"
	"testing"
)

const podUID = "11111111-2222-3333-4444-555555555555"

func TestProfileFor(t *testing.T) {
	cases := []struct {
		role       Role
		ns, ksa    string
		wantSAN    string
		clientOnly bool
	}{
		{RoleService, "agent-control", "policy-gateway", "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway", false},
		{RoleAdapter, "agent-adapters", "model-adapter", "spiffe://agentarium.internal/ns/agent-adapters/sa/model-adapter", false},
		{RoleRuntime, "agent-exec", "agent-runtime", "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/" + podUID, true},
		{RoleProbe, "agent-adapters", "probe-runner", "spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/pod/" + podUID, true},
	}
	for _, c := range cases {
		p, err := ProfileFor(c.role, c.ns, c.ksa, podUID)
		if err != nil {
			t.Fatalf("%s: %v", c.role, err)
		}
		if p.SAN != c.wantSAN || p.ClientOnly != c.clientOnly || p.Lifetime != Lifetime {
			t.Errorf("%s: got %+v", c.role, p)
		}
	}
	if _, err := ProfileFor(RoleNodeBridge, "agent-sensors", "runtime-guard", podUID); !errors.Is(err, ErrNodeBridgeDisabled) {
		t.Errorf("node bridge: %v", err)
	}
	for _, bad := range [][3]string{{"Agent-Exec", "x", podUID}, {"agent-exec", "a/b", podUID}, {"agent-exec", "agent-runtime", "not-a-uid"}} {
		if _, err := ProfileFor(RoleRuntime, bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	if _, err := ProfileFor("admin", "agent-exec", "x", podUID); err == nil {
		t.Error("unknown role accepted")
	}
}

func csrPEM(t *testing.T, key any, uris ...string) []byte {
	t.Helper()
	var us []*url.URL
	for _, u := range uris {
		p, _ := url.Parse(u)
		us = append(us, p)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}, URIs: us}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestParseCSR(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	want, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	// The CSR asks for an admin SAN; ParseCSR returns only the public key.
	got, err := ParseCSR(csrPEM(t, ec, "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity"))
	if err != nil || string(got) != string(want) {
		t.Fatalf("p256: %v", err)
	}

	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := ParseCSR(csrPEM(t, rk)); err == nil {
		t.Error("RSA accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := ParseCSR(csrPEM(t, p384)); err == nil {
		t.Error("P-384 accepted")
	}

	good := csrPEM(t, ec)
	block, _ := pem.Decode(good)
	block.Bytes[len(block.Bytes)-3] ^= 0xff
	if _, err := ParseCSR(pem.EncodeToMemory(block)); err == nil {
		t.Error("tampered signature accepted")
	}
	if _, err := ParseCSR(append(append([]byte{}, good...), good...)); err == nil {
		t.Error("two CSRs accepted")
	}
	if _, err := ParseCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})); err == nil {
		t.Error("wrong PEM type accepted")
	}
	if _, err := ParseCSR(make([]byte, MaxCSRBytes+1)); err == nil {
		t.Error("oversized input accepted")
	}
	exact := append(append([]byte{}, good...), bytes.Repeat([]byte("\n"), MaxCSRBytes-len(good))...)
	if _, err := ParseCSR(exact); err != nil {
		t.Errorf("CSR of exactly MaxCSRBytes rejected: %v", err)
	}
	if _, err := ParseCSR(append(exact, '\n')); err == nil {
		t.Error("valid CSR over MaxCSRBytes accepted")
	}
	if _, err := ParseCSR(nil); err == nil {
		t.Error("empty input accepted")
	}
	if _, err := ParseCSR(append([]byte("junk\n"), good...)); err == nil {
		t.Error("text before the PEM block accepted")
	}
	fresh, _ := pem.Decode(csrPEM(t, ec))
	fresh.Headers = map[string]string{"X": "y"}
	if _, err := ParseCSR(pem.EncodeToMemory(fresh)); err == nil {
		t.Error("PEM headers accepted")
	}
	padded := append([]byte("\n\r\n"), good...)
	if _, err := ParseCSR(append(padded, "\n\n"...)); err != nil {
		t.Errorf("surrounding whitespace rejected: %v", err)
	}
}

// TestParseCSREnvelope pins the PEM envelope rules: only whitespace may
// surround the single CERTIFICATE REQUEST block, and pem.Decode must not be
// allowed to skip an earlier block.
func TestParseCSREnvelope(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := csrPEM(t, ec)
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	other := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}})
	malformed := []byte("-----BEGIN CERTIFICATE REQUEST-----\nnot base64!\n-----END CERTIFICATE REQUEST-----\n")

	accept := map[string][]byte{
		"plain":                    good,
		"leading newlines":         cat([]byte("\n\r\n"), good),
		"leading same-line space":  cat([]byte("  "), good),
		"leading same-line tab":    cat([]byte("\t"), good),
		"leading mixed whitespace": cat([]byte(" \n\t\r\n "), good),
		"trailing whitespace":      cat(good, []byte(" \t\r\n\n")),
		"no trailing newline":      bytes.TrimRight(good, "\n"),
		"surrounded by whitespace": cat([]byte("\n \t"), good, []byte("\n\n ")),
	}
	for name, in := range accept {
		if _, err := ParseCSR(in); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}

	reject := map[string][]byte{
		"leading garbage":                cat([]byte("junk\n"), good),
		"leading garbage same line":      cat([]byte("x"), good),
		"leading non-space control byte": cat([]byte("\v"), good),
		"leading malformed PEM block":    cat(malformed, good),
		"leading valid other-type block": cat(other, good),
		"leading valid CSR then another": cat(good, good),
		"trailing garbage":               cat(good, []byte("junk")),
		"trailing garbage after newline": cat(good, []byte("\n\njunk\n")),
		"trailing second PEM block":      cat(good, other),
		"trailing malformed PEM block":   cat(good, malformed),
		"malformed block only":           malformed,
		"other-type block only":          other,
		"whitespace only":                []byte(" \n\t\r\n"),
	}
	for name, in := range reject {
		if _, err := ParseCSR(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	withHeaders, _ := pem.Decode(good)
	withHeaders.Headers = map[string]string{"Proc-Type": "4,ENCRYPTED"}
	if _, err := ParseCSR(cat([]byte(" \n"), pem.EncodeToMemory(withHeaders))); err == nil {
		t.Error("PEM headers after leading whitespace accepted")
	}

	// Size is checked on the raw input, before trimming.
	lead := cat(bytes.Repeat([]byte(" "), MaxCSRBytes-len(good)), good)
	if _, err := ParseCSR(lead); err != nil {
		t.Errorf("leading-padded CSR of exactly MaxCSRBytes rejected: %v", err)
	}
	if _, err := ParseCSR(cat([]byte(" "), lead)); err == nil {
		t.Error("leading-padded CSR over MaxCSRBytes accepted")
	}
}
