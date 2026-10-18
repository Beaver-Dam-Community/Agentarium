package sessions

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
	"github.com/jackc/pgx/v5"
	"github.com/open-policy-agent/opa/v1/bundle"
)

// The storage transport is local. The signed tarball, signature verification,
// catalog validation and snapshot replacement all use production code.
type policyFixture struct {
	mu          sync.Mutex
	desired     policyloader.Desired
	object      []byte
	key, public string
	active      ActiveBundle
	activeErr   error
	epoch       int64
	reads       []Querier
}

// noQuerier stands in for the pool in unit tests; the fixture reader never
// executes SQL. PostgreSQL tests use the real transaction.
type noQuerier struct{}

func (noQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func (f *policyFixture) Desired(context.Context) (policyloader.Desired, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.desired, nil
}
func (f *policyFixture) Fetch(context.Context, string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.object...), nil
}
func (f *policyFixture) ActivePolicy(_ context.Context, q Querier, environment string) (ActiveBundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = append(f.reads, q)
	if environment != "test" {
		return ActiveBundle{}, errors.New("wrong environment")
	}
	return f.active, f.activeErr
}
func (f *policyFixture) activate(l *policyloader.Loader) {
	snap := l.Current()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.epoch++
	f.active = ActiveBundle{ScopeID: "test", BundleID: snap.BundleID(), ArtifactDigest: snap.ArtifactDigest(), ExpectedOPARevision: snap.Revision(), Epoch: f.epoch}
}
func (f *policyFixture) policy(l *policyloader.Loader) SnapshotPolicy {
	return SnapshotPolicy{Loader: l, Active: f, Environment: "test", DB: noQuerier{}}
}

func newPolicyFixture(t *testing.T) (*policyFixture, *policyloader.Loader) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &policyFixture{key: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})), public: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))}
	loader, err := policyloader.New(policyloader.Config{Source: f, Fetcher: f, Keys: map[string]string{"prod-v1": f.public}, KeyID: "prod-v1"})
	if err != nil {
		t.Fatal(err)
	}
	return f, loader
}
func policyRules(budget int) map[string]any {
	return map[string]any{"standing.k8s_read.v1": map[string]any{"standing_rule_id": "standing.k8s_read.v1", "session_kind": "user", "operation_ids": []string{"k8s.pods.list", "k8s.pods.logs"}, "target_pattern": "k8s-agent-targets", "session_budget": budget, "limits": map[string]any{"limit": 100}, "profile": nil, "data_profile": "synthetic"}}
}
func (f *policyFixture) put(t *testing.T, marker string, rules any, signed bool) {
	t.Helper()
	cat, err := canonical.LoadCatalogDir("../../../../packages/canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	op := cat.Operations["k8s.pods.list"]
	op.Description = marker
	cat.Operations[op.OperationID] = op
	cat.CatalogDigest, err = cat.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	var cd any
	if err = json.Unmarshal(raw, &cd); err != nil {
		t.Fatal(err)
	}
	b := bundle.Bundle{Manifest: bundle.Manifest{Revision: marker}, Data: map[string]any{"catalog": cd, "standing_rules": rules}}
	if signed {
		if err = b.GenerateSignature(bundle.NewSigningConfig(f.key, "ES256", ""), "prod-v1", false); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err = bundle.NewWriter(&buf).Write(b); err != nil {
		t.Fatal(err)
	}
	digest := canonical.SHA256Hex(buf.Bytes())
	f.mu.Lock()
	defer f.mu.Unlock()
	f.object = buf.Bytes()
	f.desired = policyloader.Desired{BundleID: marker, ArtifactDigest: digest, ObjectURI: "gs://test/bundles/" + digest + ".tar.gz"}
}
func TestSnapshotPolicyVerifiedAndIsolated(t *testing.T) {
	ctx := context.Background()
	f, loader := newPolicyFixture(t)
	p := f.policy(loader)
	for _, empty := range []SnapshotPolicy{{}, p} {
		if _, err := empty.Policy(ctx); !errors.Is(err, ErrPolicyUnavailable) {
			t.Fatalf("empty policy: %v", err)
		}
	}
	f.put(t, "unsigned", policyRules(100), false)
	if err := loader.Poll(ctx); err == nil {
		t.Fatal("unsigned bundle accepted")
	}
	if _, err := p.Policy(ctx); !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("unsigned policy: %v", err)
	}
	f.put(t, "100", policyRules(100), true)
	if err := loader.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	f.activate(loader)
	first, err := p.Policy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.Catalog.Operations["k8s.pods.list"].Description != "100" || first.StandingRules["standing.k8s_read.v1"].SessionBudget != 100 {
		t.Fatalf("policy: %+v", first)
	}
	r := first.StandingRules["standing.k8s_read.v1"]
	r.OperationIDs[0] = "forged"
	first.StandingRules["standing.k8s_read.v1"] = r
	delete(first.Catalog.Operations, "k8s.pods.list")
	again, err := p.Policy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.StandingRules["standing.k8s_read.v1"].OperationIDs[0] != "k8s.pods.list" || len(again.Catalog.Operations) == len(first.Catalog.Operations) {
		t.Fatal("caller mutated snapshot")
	}
	f.put(t, "200", policyRules(200), false)
	if err := loader.Poll(ctx); err == nil {
		t.Fatal("unsigned update accepted")
	}
	preserved, err := p.Policy(ctx)
	if err != nil || preserved.StandingRules["standing.k8s_read.v1"].SessionBudget != 100 {
		t.Fatalf("failed update changed policy: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.Policy(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}
func TestSnapshotPolicyRejectsMalformedRules(t *testing.T) {
	cases := map[string]func(map[string]any) any{
		"missing": func(r map[string]any) any { return nil },
		"array":   func(r map[string]any) any { return []any{} },
		"wrong_id": func(r map[string]any) any {
			r["standing.k8s_read.v1"].(map[string]any)["standing_rule_id"] = "other"
			return r
		},
		"wrong_case_budget": func(r map[string]any) any {
			row := r["standing.k8s_read.v1"].(map[string]any)
			row["SESSION_BUDGET"] = row["session_budget"]
			delete(row, "session_budget")
			return r
		},
		"null_rule": func(r map[string]any) any { r["standing.k8s_read.v1"] = nil; return r },
		"missing_budget": func(r map[string]any) any {
			delete(r["standing.k8s_read.v1"].(map[string]any), "session_budget")
			return r
		},
		"fraction_budget": func(r map[string]any) any {
			r["standing.k8s_read.v1"].(map[string]any)["session_budget"] = 1.5
			return r
		},
		"negative_budget": func(r map[string]any) any {
			r["standing.k8s_read.v1"].(map[string]any)["session_budget"] = -1
			return r
		},
		"unsafe_budget": func(r map[string]any) any {
			r["standing.k8s_read.v1"].(map[string]any)["session_budget"] = int64(1 << 53)
			return r
		},
		"bad_kind": func(r map[string]any) any {
			r["standing.k8s_read.v1"].(map[string]any)["session_kind"] = "any"
			return r
		},
		"bad_pattern": func(r map[string]any) any {
			r["standing.k8s_read.v1"].(map[string]any)["target_pattern"] = "["
			return r
		},
		"empty_operations": func(r map[string]any) any {
			r["standing.k8s_read.v1"].(map[string]any)["operation_ids"] = []string{}
			return r
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f, l := newPolicyFixture(t)
			f.put(t, name, mutate(policyRules(100)), true)
			if err := l.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.activate(l)
			pol, err := f.policy(l).Policy(context.Background())
			if !errors.Is(err, ErrPolicyUnavailable) || pol.StandingRules != nil {
				t.Fatalf("invalid policy exposed: %+v %v", pol, err)
			}
		})
	}
}
func TestSnapshotPolicyReloadKeepsCatalogAndBudgetTogether(t *testing.T) {
	ctx := context.Background()
	f, l := newPolicyFixture(t)
	f.put(t, "1", policyRules(1), true)
	if err := l.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	f.activate(l)
	p := f.policy(l)
	errs := make(chan error, 4)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				got, err := p.Policy(ctx)
				if errors.Is(err, ErrPolicyUnavailable) || errors.Is(err, ErrPolicyVersionMismatch) {
					continue
				} // preload/activation transition
				if err != nil {
					errs <- err
					return
				}
				if got.Catalog.Operations["k8s.pods.list"].Description != fmt.Sprint(got.StandingRules["standing.k8s_read.v1"].SessionBudget) {
					errs <- errors.New("mixed snapshot")
					return
				}
			}
		}()
	}
	for i := 2; i < 8; i++ {
		f.put(t, fmt.Sprint(i), policyRules(i), true)
		if err := l.Poll(ctx); err != nil {
			t.Fatal(err)
		}
		f.activate(l)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSnapshotPolicyRequiresMatchingActivation(t *testing.T) {
	ctx := context.Background()
	f, l := newPolicyFixture(t)
	f.put(t, "loaded", policyRules(100), true)
	if err := l.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SnapshotPolicy){
		"nil_reader":         func(p *SnapshotPolicy) { p.Active = nil },
		"no_environment":     func(p *SnapshotPolicy) { p.Environment = "" },
		"missing_active_row": func(p *SnapshotPolicy) { f.active = ActiveBundle{} },
		"reader_failure":     func(p *SnapshotPolicy) { f.activeErr = errors.New("database unavailable") },
		"no_querier":         func(p *SnapshotPolicy) { p.DB = nil },
		"zero_epoch":         func(p *SnapshotPolicy) { f.active.Epoch = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			f.activate(l)
			f.activeErr = nil
			p := f.policy(l)
			mutate(&p)
			got, err := p.Policy(ctx)
			if !errors.Is(err, ErrPolicyUnavailable) || got.StandingRules != nil {
				t.Fatalf("unmatched active policy exposed: %+v %v", got, err)
			}
		})
	}
	// A loaded bundle that is not the active revision is COMMON
	// POLICY_VERSION_MISMATCH, distinct from "nothing loaded".
	for name, mutate := range map[string]func(){
		"wrong_environment": func() { f.active.ScopeID = "regression" },
		"wrong_bundle":      func() { f.active.BundleID = "other" },
		"wrong_digest":      func() { f.active.ArtifactDigest = canonical.SHA256Hex([]byte("other")) },
		"wrong_revision":    func() { f.active.ExpectedOPARevision = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			f.activate(l)
			f.activeErr = nil
			mutate()
			got, err := f.policy(l).Policy(ctx)
			if !errors.Is(err, ErrPolicyVersionMismatch) || got.StandingRules != nil {
				t.Fatalf("unmatched active policy exposed: %+v %v", got, err)
			}
			if e := PolicyError(err); e.Code != "POLICY_VERSION_MISMATCH" || e.Status != http.StatusServiceUnavailable {
				t.Fatalf("mapped to %+v", e)
			}
		})
	}
	f.activate(l)
	f.activeErr = nil
	// Loading the next desired bundle does not activate it.
	f.put(t, "next", policyRules(200), true)
	if err := l.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.policy(l).Policy(ctx); !errors.Is(err, ErrPolicyVersionMismatch) {
		t.Fatalf("preloaded snapshot accepted: %v", err)
	}
	f.activate(l)
	got, err := f.policy(l).Policy(ctx)
	if err != nil || got.StandingRules["standing.k8s_read.v1"].SessionBudget != 200 || got.Epoch != f.epoch {
		t.Fatalf("activated snapshot unavailable: %+v %v", got, err)
	}
	// PolicyIn reads through the caller's querier, never the configured pool.
	var tx noQuerier
	f.reads = nil
	if _, err := f.policy(l).PolicyIn(ctx, tx); err != nil || len(f.reads) != 1 || f.reads[0] != Querier(tx) {
		t.Fatalf("PolicyIn did not use the caller querier: %v %v", err, f.reads)
	}
}
