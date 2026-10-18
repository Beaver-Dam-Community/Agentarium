package receipt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func fixture() (Expected, Receipt) {
	action := uuid.NewString()
	digest := strings.Repeat("a", 64)
	return Expected{ActionID: action, TargetID: "receiver-primary", RouteID: "submissions-v1", WireBodyDigest: digest}, Receipt{ActionKey: action, TargetIdentity: "receiver-primary", Route: "submissions-v1", ReceiverMode: "idempotent", TargetVersion: "test-v1", EffectCount: 1, Effects: []Effect{{EffectID: uuid.NewString(), WireBodyDigest: digest, BodyBytes: 4, CommittedAt: "2026-10-17T00:00:00Z"}}, ReceiverAttempts: []Attempt{{ReceiptAttemptID: uuid.NewString(), WireBodyDigest: digest, ReceivedAt: "2026-10-17T00:00:00Z", Outcome: "effect_created"}}}
}
func TestRules(t *testing.T) {
	cases := []struct {
		name, rule, level string
		mutate            func(*Expected, *Receipt)
	}{
		{"one effect", "R1", "effect_verified", func(*Expected, *Receipt) {}},
		{"digest mismatch", "R2", "effect_mismatch", func(w *Expected, r *Receipt) { w.WireBodyDigest = strings.Repeat("b", 64) }},
		{"target mismatch", "R2", "effect_mismatch", func(w *Expected, r *Receipt) { w.TargetID = "other" }},
		{"route mismatch", "R2", "effect_mismatch", func(w *Expected, r *Receipt) { w.RouteID = "other" }},
		{"committed effect then mutated conflict", "R2", "effect_mismatch", func(w *Expected, r *Receipt) {
			a := r.ReceiverAttempts[0]
			a.ReceiptAttemptID = uuid.NewString()
			a.WireBodyDigest = strings.Repeat("b", 64)
			a.Outcome = "key_body_conflict"
			r.ReceiverAttempts = append(r.ReceiverAttempts, a)
		}},
		{"attempt mismatch without key rejection", "R2", "effect_mismatch", func(w *Expected, r *Receipt) {
			r.ReceiverAttempts[0].WireBodyDigest = strings.Repeat("b", 64)
		}},
		{"attempt mismatch without effect", "R2", "effect_mismatch", func(w *Expected, r *Receipt) {
			r.Effects = []Effect{}
			r.EffectCount = 0
			r.ReceiverAttempts[0].Outcome = "key_body_conflict"
			r.ReceiverAttempts[0].WireBodyDigest = strings.Repeat("b", 64)
		}},
		{"multiple effects", "R2", "effect_mismatch", func(w *Expected, r *Receipt) {
			e := r.Effects[0]
			e.EffectID = uuid.NewString()
			e.WireBodyDigest = strings.Repeat("b", 64)
			r.Effects = append(r.Effects, e)
			r.EffectCount = 2
			a := r.ReceiverAttempts[0]
			a.ReceiptAttemptID = uuid.NewString()
			a.WireBodyDigest = e.WireBodyDigest
			r.ReceiverAttempts = append(r.ReceiverAttempts, a)
		}},
		{"conflict no effect", "R3", "effect_mismatch", func(w *Expected, r *Receipt) {
			r.Effects = []Effect{}
			r.EffectCount = 0
			r.ReceiverAttempts[0].Outcome = "key_body_conflict"
			w.AttemptFailed = true
		}},
		{"missing key no effect", "R3", "effect_mismatch", func(w *Expected, r *Receipt) {
			r.Effects = []Effect{}
			r.EffectCount = 0
			r.ReceiverAttempts[0].Outcome = "key_missing_rejected"
		}},
		{"empty receipt", "R5", "unknown", func(w *Expected, r *Receipt) {
			r.Effects = []Effect{}
			r.EffectCount = 0
			r.ReceiverAttempts = []Attempt{}
		}},
		{"empty receipt wrong destination", "R5", "unknown", func(w *Expected, r *Receipt) {
			r.Effects, r.ReceiverAttempts = []Effect{}, []Attempt{}
			r.EffectCount = 0
			w.TargetID, w.RouteID = "other-target", "other-route"
		}},
		{"failed empty receipt wrong destination", "R6", "none", func(w *Expected, r *Receipt) {
			r.Effects, r.ReceiverAttempts = []Effect{}, []Attempt{}
			r.EffectCount = 0
			w.TargetID, w.RouteID = "other-target", "other-route"
			w.AttemptFailed = true
		}},
		{"failed before send empty receipt", "R6", "none", func(w *Expected, r *Receipt) {
			w.AttemptFailed = true
			r.Effects = []Effect{}
			r.EffectCount = 0
			r.ReceiverAttempts = []Attempt{}
		}},
		{"independent effect beats attempt_failed", "R1", "effect_verified", func(w *Expected, r *Receipt) { w.AttemptFailed = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, r := fixture()
			tc.mutate(&w, &r)
			raw, _ := json.Marshal(r)
			decoded, digest, err := decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			result, err := classify(w, decoded, digest)
			if err != nil || result.RuleID != tc.rule || result.EvidenceLevel != tc.level || result.Receipt.EffectCount != r.EffectCount || len(result.Receipt.Effects) != len(r.Effects) {
				t.Fatalf("result %+v %v", result, err)
			}
			if len(r.Effects) > 1 && result.Receipt.Effects[1].WireBodyDigest != r.Effects[1].WireBodyDigest {
				t.Fatal("discarded extra independent digest")
			}
		})
	}
}

func TestEffectCreatedRequiresEffect(t *testing.T) {
	w, r := fixture()
	r.Effects = []Effect{}
	r.EffectCount = 0
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decode(raw); err == nil {
		t.Fatal("effect_created without effect accepted by decoder")
	}
	if result, err := classify(w, &r, ""); err == nil || result.EvidenceLevel != "" {
		t.Fatal("inconsistent receipt classified", result, err)
	}
}
func TestEffectRequiresEffectCreatedAttempt(t *testing.T) {
	for name, mutate := range map[string]func(*Receipt){
		"no attempts":    func(r *Receipt) { r.ReceiverAttempts = []Attempt{} },
		"only duplicate": func(r *Receipt) { r.ReceiverAttempts[0].Outcome = "duplicate_returned" },
		"two created one effect": func(r *Receipt) {
			a := r.ReceiverAttempts[0]
			a.ReceiptAttemptID = uuid.NewString()
			r.ReceiverAttempts = append(r.ReceiverAttempts, a)
		},
	} {
		t.Run(name, func(t *testing.T) {
			w, r := fixture()
			mutate(&r)
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := decode(raw); err == nil {
				t.Fatal("effect without matching effect_created attempt accepted")
			}
			if result, err := classify(w, &r, ""); err == nil || result.EvidenceLevel != "" {
				t.Fatal("inconsistent receipt classified", result, err)
			}
		})
	}
}

func TestStrictReceipt(t *testing.T) {
	_, r := fixture()
	b, _ := json.Marshal(r)
	raw := string(b)
	cases := map[string]string{
		"top-level case alias":         strings.Replace(raw, `"effect_count":1`, `"TARGET_IDENTITY":"receiver-primary","effect_count":1`, 1),
		"effect case alias":            strings.Replace(raw, `"body_bytes":4`, `"WIRE_BODY_DIGEST":"`+strings.Repeat("b", 64)+`","body_bytes":4`, 1),
		"attempt optional alias":       strings.Replace(raw, `"client_attempt_id":null`, `"client_attempt_id":null,"CLIENT_ATTEMPT_ID":null`, 1),
		"duplicate key":                strings.Replace(raw, `"effect_count":1`, `"effect_count":1,"effect_count":1`, 1),
		"unknown field":                strings.Replace(raw, `"effect_count":1`, `"other":1,"effect_count":1`, 1),
		"missing zero-sensitive field": strings.Replace(raw, `"body_bytes":4,`, "", 1),
		"null count":                   strings.Replace(raw, `"effect_count":1`, `"effect_count":null`, 1),
		"null array":                   strings.Replace(raw, `"effects":[`, `"effects":null,"x":[`, 1),
		"inconsistent count":           strings.Replace(raw, `"effect_count":1`, `"effect_count":2`, 1),
		"negative bytes":               strings.Replace(raw, `"body_bytes":4`, `"body_bytes":-1`, 1),
		"invalid digest":               strings.Replace(raw, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"unknown outcome":              strings.Replace(raw, `effect_created`, `invented`, 1),
		"invalid date":                 strings.Replace(raw, `2026-10-17T00:00:00Z`, `yesterday`, 1),
		"trailing JSON":                raw + `{}`,
		"oversize":                     `{"oversize":"` + strings.Repeat("x", 1<<20) + `"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decode([]byte(raw)); err == nil {
				t.Fatal("malformed receipt accepted")
			}
		})
	}
	// Whitespace/key order do not alter the digest. Omitted optional fields do:
	// digest the actual wire JSON, not a typed reserialization inserting nulls.
	_, d1, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	var pretty any
	_ = json.Unmarshal(b, &pretty)
	reordered, _ := json.MarshalIndent(pretty, "", "  ")
	_, d2, err := decode(reordered)
	if err != nil || d1 != d2 {
		t.Fatal("not JCS stable", err)
	}
	omitted := strings.Replace(raw, `"content_digest_server":null,`, "", 1)
	_, d3, err := decode([]byte(omitted))
	if err != nil || d1 == d3 {
		t.Fatal("optional presence was normalized", err)
	}
}

type certificates struct {
	dir, ca string
	root    *x509.Certificate
	key     *ecdsa.PrivateKey
	roots   *x509.CertPool
}

func testCA(t *testing.T) *certificates {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &certificates{dir: dir, ca: ca, root: root, key: key, roots: roots}
}
func (c *certificates) leaf(t *testing.T, name, san string, usage x509.ExtKeyUsage) (string, string, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(san)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{SerialNumber: serial, NotBefore: c.root.NotBefore, NotAfter: c.root.NotAfter, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.root, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cp, kp := filepath.Join(c.dir, name+".crt"), filepath.Join(c.dir, name+".key")
	if err = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0600); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	return cp, kp, cert
}
func TestMTLSClient(t *testing.T) {
	ca := testCA(t)
	cp, kp, _ := ca.leaf(t, "collector", CollectorSAN, x509.ExtKeyUsageClientAuth)
	for _, tc := range []struct {
		name, san string
		status    int
		body      func(Receipt) string
		valid     bool
	}{
		{"valid", ReceiverSAN, 200, func(r Receipt) string { b, _ := json.Marshal(r); return string(b) }, true},
		{"wrong source", "spiffe://agentarium.internal/ns/agent-targets/sa/other", 200, func(r Receipt) string { b, _ := json.Marshal(r); return string(b) }, false},
		{"redirect", ReceiverSAN, 302, func(Receipt) string { return "" }, false},
		{"not found is not none", ReceiverSAN, 404, func(Receipt) string { return "" }, false},
		{"outage is not none", ReceiverSAN, 503, func(Receipt) string { return "" }, false},
		{"wrong key", ReceiverSAN, 200, func(r Receipt) string { r.ActionKey = uuid.NewString(); b, _ := json.Marshal(r); return string(b) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, serverCert := ca.leaf(t, tc.name, tc.san, x509.ExtKeyUsageServerAuth)
			w, r := fixture()
			w.AttemptFailed = true
			hits := 0
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(out http.ResponseWriter, req *http.Request) {
				hits++
				if req.URL.Path != "/test/v1/receipts/"+w.ActionID {
					t.Error("wrong receipt path")
				}
				if len(req.TLS.VerifiedChains) == 0 || req.TLS.PeerCertificates[0].URIs[0].String() != CollectorSAN {
					t.Error("collector not authenticated")
				}
				out.Header().Set("Location", "https://invalid.example/should-not-follow")
				out.WriteHeader(tc.status)
				fmt.Fprint(out, tc.body(r))
			}))
			s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientCAs: ca.roots, ClientAuth: tls.RequireAndVerifyClientCert}
			s.StartTLS()
			defer s.Close()
			client, err := NewClient(s.URL, cp, kp, ca.ca)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Check(context.Background(), w)
			if tc.valid {
				if err != nil || result.RuleID != "R1" {
					t.Fatalf("%+v %v", result, err)
				}
			} else if err == nil || result.EvidenceLevel != "" {
				t.Fatal("untrusted response classified", result)
			}
			if tc.status == 302 && hits != 1 {
				t.Fatal("redirect followed")
			}
		})
	}
	t.Run("wrong caller", func(t *testing.T) {
		badcp, badkp, _ := ca.leaf(t, "adapter", "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender", x509.ExtKeyUsageClientAuth)
		if _, err := NewClient("https://receiver.invalid", badcp, badkp, ca.ca); err == nil {
			t.Fatal("adapter identity accepted")
		}
	})
	t.Run("untrusted CA", func(t *testing.T) {
		other := testCA(t)
		_, _, serverCert := other.leaf(t, "receiver", ReceiverSAN, x509.ExtKeyUsageServerAuth)
		s := httptest.NewUnstartedServer(http.NotFoundHandler())
		s.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: ca.roots, ClientAuth: tls.RequireAndVerifyClientCert}
		s.StartTLS()
		defer s.Close()
		c, err := NewClient(s.URL, cp, kp, ca.ca)
		if err != nil {
			t.Fatal(err)
		}
		w, _ := fixture()
		if _, err = c.Check(context.Background(), w); err == nil {
			t.Fatal("untrusted receiver accepted")
		}
	})
}
func TestActualWireDigest(t *testing.T) {
	_, r := fixture()
	raw, _ := json.Marshal(r)
	_, digest, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if digest == hex.EncodeToString(sum[:]) {
		t.Fatal("fixture must exercise key canonicalization")
	}
}
