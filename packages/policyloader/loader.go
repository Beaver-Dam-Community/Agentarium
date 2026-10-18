// Package policyloader loads the signed policy bundle that desired_bundle
// points to (TASK-04 3.1, COMMON policy decision contract). The gateway, the adapters and
// tools/decision-replay share it.
//
// Every Poll reads the desired_bundle row. When the row differs from what is
// loaded, the loader downloads the object, checks its SHA-256 against
// artifact_digest, reads it with OPA's bundle reader and a verification config
// whose keyID is set (so an unsigned bundle is rejected), rejects an empty
// manifest revision, re-checks data.catalog with canonical.ParseBundleCatalog,
// optionally prepares the gateway query, reads the desired row again, and only
// then swaps the snapshot atomically. On any failure the previous snapshot
// stays in use and the failure is recorded in Status.
package policyloader

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// GatewayQuery is the query the gateway prepares (TASK-04 3.1 step 4).
const GatewayQuery = "data.agentarium.gateway.result"

// PollInterval is the desired_bundle polling period (TASK-04 9).
const PollInterval = 2 * time.Second

// Desired is one desired_bundle row. Loads compare the whole tuple, so the
// same artifact under another bundle_id is loaded again with the new id.
type Desired struct {
	BundleID       string
	ArtifactDigest string
	ObjectURI      string
}

// Source reads the desired_bundle row of this environment.
type Source interface {
	Desired(ctx context.Context) (Desired, error)
}

// Fetcher returns the object at a gs:// URI. Implementations must stop after
// MaxObjectBytes+1 bytes so an oversize object is detected.
type Fetcher interface {
	Fetch(ctx context.Context, uri string) ([]byte, error)
}

// Config configures a Loader.
type Config struct {
	Source  Source
	Fetcher Fetcher
	// Keys maps keyID to a PEM "PUBLIC KEY" (ConfigMap agentarium-bundle-keys).
	Keys map[string]string
	// KeyID is the only key this process trusts: prod-v1, or regression-v1 in
	// the regression project.
	KeyID string
	// Query, if set, is prepared against each bundle (GatewayQuery for the
	// gateway). Adapters and decision-replay leave it empty and use Data.
	Query string
	// OnLoaded runs after a new snapshot is swapped in and Status updated.
	// OnFailed runs after a failed load is recorded; the previous snapshot is
	// still current. Both are observation hooks (the gateway connects the
	// policy_bundle_loaded / policy_bundle_load_failed audit events to them);
	// they do not guarantee an audit record, and an error they return is
	// reported by Poll without undoing the load.
	OnLoaded func(Status) error
	OnFailed func(Status, error) error
}

// Snapshot is one loaded bundle. It is immutable after the swap.
type Snapshot struct {
	desired  Desired
	revision string
	catalog  []byte // validated data.catalog JSON
	data     []byte // bundle data as JSON
	prepared *rego.PreparedEvalQuery
	loadedAt time.Time
}

func (s *Snapshot) BundleID() string       { return s.desired.BundleID }
func (s *Snapshot) ArtifactDigest() string { return s.desired.ArtifactDigest }
func (s *Snapshot) ObjectURI() string      { return s.desired.ObjectURI }

// Revision is the bundle .manifest revision (opa_bundle_revision).
func (s *Snapshot) Revision() string    { return s.revision }
func (s *Snapshot) LoadedAt() time.Time { return s.loadedAt }

// Catalog decodes a fresh copy of the bundle's data.catalog, which was
// validated with canonical.ParseBundleCatalog at load time. Callers may modify
// the copy; the snapshot itself never changes.
func (s *Snapshot) Catalog() (canonical.Catalog, error) {
	var c canonical.Catalog
	err := json.Unmarshal(s.catalog, &c)
	return c, err
}

// Data decodes a fresh copy of the bundle data document.
func (s *Snapshot) Data() (map[string]any, error) {
	var d map[string]any
	dec := json.NewDecoder(bytes.NewReader(s.data))
	dec.UseNumber()
	return d, dec.Decode(&d)
}

// Prepared returns the prepared query, or nil when Config.Query was empty.
// rego.PreparedEvalQuery is safe for concurrent Eval.
func (s *Snapshot) Prepared() *rego.PreparedEvalQuery { return s.prepared }

// Status is what the lease reports (loaded_artifact_digest and the last
// failure).
type Status struct {
	Loaded      Desired // zero until the first load
	Revision    string
	LastAttempt Desired
	LastError   string // empty after a successful load
	At          time.Time
}

// Loader polls desired_bundle and keeps the current snapshot.
type Loader struct {
	cfg     Config
	keys    map[string]*bundle.KeyConfig
	pollMu  sync.Mutex
	current atomic.Pointer[Snapshot]
	status  atomic.Pointer[Status]
	now     func() time.Time
}

// New validates cfg. The trusted key must exist and be an ECDSA P-256 public
// key; the key map is copied.
func New(cfg Config) (*Loader, error) {
	if cfg.Source == nil || cfg.Fetcher == nil {
		return nil, errors.New("policyloader: Source and Fetcher are required")
	}
	if cfg.KeyID == "" {
		return nil, errors.New("policyloader: empty KeyID")
	}
	pemKey, ok := cfg.Keys[cfg.KeyID]
	if !ok {
		return nil, fmt.Errorf("policyloader: no key %q", cfg.KeyID)
	}
	if err := checkPublicKey(pemKey); err != nil {
		return nil, err
	}
	// Only the trusted key goes into the verification config.
	keys := map[string]*bundle.KeyConfig{cfg.KeyID: {Key: pemKey, Algorithm: "ES256"}}
	l := &Loader{cfg: cfg, keys: keys, now: time.Now}
	l.status.Store(&Status{})
	return l, nil
}

func checkPublicKey(p string) error {
	block, _ := pem.Decode([]byte(p))
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("policyloader: key is not a PEM PUBLIC KEY")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("policyloader: key: %w", err)
	}
	if ec, ok := k.(*ecdsa.PublicKey); !ok || ec.Curve != elliptic.P256() {
		return errors.New("policyloader: key is not ECDSA P-256 (ES256)")
	}
	return nil
}

// Current returns the loaded snapshot, or nil before the first successful
// load (readiness false; the gateway answers 503 POLICY_UNAVAILABLE).
func (l *Loader) Current() *Snapshot { return l.current.Load() }

// Status returns the latest status.
func (l *Loader) Status() Status { return *l.status.Load() }

// Run polls immediately and then every PollInterval until ctx ends.
func (l *Loader) Run(ctx context.Context) {
	t := time.NewTicker(PollInterval)
	defer t.Stop()
	for {
		_ = l.Poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ErrDesiredChanged means desired_bundle changed while a bundle was being
// loaded; the bundle was not used and the next Poll loads the new row.
var ErrDesiredChanged = errors.New("policyloader: desired_bundle changed during load")

// Poll checks desired_bundle once and loads it if it differs from the current
// snapshot. Calls are serialized. It returns the load error, or an observer
// error from OnLoaded / OnFailed.
func (l *Loader) Poll(ctx context.Context) error {
	l.pollMu.Lock()
	defer l.pollMu.Unlock()

	d, err := l.cfg.Source.Desired(ctx)
	if err != nil {
		return l.fail(Desired{}, fmt.Errorf("policyloader: desired_bundle: %w", err))
	}
	if cur := l.current.Load(); cur != nil && cur.desired == d {
		// desired_bundle points at the loaded bundle again (for example after
		// a failed load was rolled back): clear the failure so the lease
		// reports healthy, without downloading or calling OnLoaded.
		if st := l.status.Load(); st.LastError != "" || st.LastAttempt != d {
			l.status.Store(&Status{Loaded: d, Revision: cur.revision, LastAttempt: d, At: l.now()})
		}
		return nil
	}
	snap, err := l.load(ctx, d)
	if err != nil {
		return l.fail(d, err)
	}
	// Publish only if desired_bundle still points at what was loaded.
	again, err := l.cfg.Source.Desired(ctx)
	if err != nil {
		return l.fail(d, fmt.Errorf("policyloader: desired_bundle recheck: %w", err))
	}
	if again != d {
		return l.fail(d, ErrDesiredChanged)
	}
	l.current.Store(snap)
	st := &Status{Loaded: d, Revision: snap.revision, LastAttempt: d, At: snap.loadedAt}
	l.status.Store(st)
	if l.cfg.OnLoaded != nil {
		if err := l.cfg.OnLoaded(*st); err != nil {
			return fmt.Errorf("policyloader: OnLoaded: %w", err)
		}
	}
	return nil
}

func (l *Loader) fail(d Desired, err error) error {
	prev := l.status.Load()
	st := &Status{Loaded: prev.Loaded, Revision: prev.Revision, LastAttempt: d, LastError: err.Error(), At: l.now()}
	l.status.Store(st)
	if l.cfg.OnFailed != nil {
		if oerr := l.cfg.OnFailed(*st, err); oerr != nil {
			return errors.Join(err, fmt.Errorf("policyloader: OnFailed: %w", oerr))
		}
	}
	return err
}

var objectURI = regexp.MustCompile(`^gs://[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]/bundles/([0-9a-f]{64})\.tar\.gz$`)

func (l *Loader) load(ctx context.Context, d Desired) (*Snapshot, error) {
	if d.BundleID == "" {
		return nil, errors.New("policyloader: empty bundle_id")
	}
	m := objectURI.FindStringSubmatch(d.ObjectURI)
	if m == nil || m[1] != d.ArtifactDigest {
		return nil, fmt.Errorf("policyloader: object_uri %q does not name artifact_digest %q", d.ObjectURI, d.ArtifactDigest)
	}
	obj, err := l.cfg.Fetcher.Fetch(ctx, d.ObjectURI)
	if err != nil {
		return nil, fmt.Errorf("policyloader: fetch: %w", err)
	}
	if len(obj) > MaxObjectBytes {
		return nil, fmt.Errorf("policyloader: object larger than %d bytes", MaxObjectBytes)
	}
	if got := canonical.SHA256Hex(obj); got != d.ArtifactDigest {
		return nil, fmt.Errorf("policyloader: object SHA-256 %s != artifact_digest %s", got, d.ArtifactDigest)
	}
	if err := checkArchive(obj); err != nil {
		return nil, err
	}
	vc := bundle.NewVerificationConfig(l.keys, l.cfg.KeyID, "", nil)
	b, err := bundle.NewCustomReader(bundle.NewTarballLoaderWithBaseURL(bytes.NewReader(obj), "")).
		WithBundleVerificationConfig(vc).
		Read()
	if err != nil {
		return nil, fmt.Errorf("policyloader: bundle: %w", err)
	}
	if b.Manifest.Revision == "" {
		return nil, errors.New("policyloader: empty manifest revision")
	}
	data, err := json.Marshal(b.Data)
	if err != nil {
		return nil, err
	}
	catRaw, ok := b.Data["catalog"]
	if !ok {
		return nil, errors.New("policyloader: bundle has no data.catalog")
	}
	catJSON, err := json.Marshal(catRaw)
	if err != nil {
		return nil, err
	}
	if _, err := canonical.ParseBundleCatalog(catJSON); err != nil {
		return nil, fmt.Errorf("policyloader: data.catalog: %w", err)
	}
	snap := &Snapshot{desired: d, revision: b.Manifest.Revision, catalog: catJSON, data: data, loadedAt: l.now()}
	if l.cfg.Query != "" {
		pq, err := rego.New(rego.Query(l.cfg.Query), rego.ParsedBundle("agentarium", &b)).PrepareForEval(ctx)
		if err != nil {
			return nil, fmt.Errorf("policyloader: prepare: %w", err)
		}
		snap.prepared = &pq
	}
	return snap, nil
}
