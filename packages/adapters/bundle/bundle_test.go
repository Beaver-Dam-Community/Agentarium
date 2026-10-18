package bundle_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/bundle"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/bundle/bundletest"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

func loader(t *testing.T, s bundletest.Signed) *policyloader.Loader {
	t.Helper()
	f := &bundletest.Fetcher{}
	f.Put(s)
	l, err := policyloader.New(policyloader.Config{
		Source: bundletest.StaticSource{Row: s.Desired()}, Fetcher: f,
		Keys: map[string]string{bundletest.KeyID: s.PublicKeyPEM}, KeyID: bundletest.KeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func catalog(t *testing.T) canonical.Catalog {
	t.Helper()
	c, err := canonical.LoadCatalogDir("../../canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var data = map[string]any{
	"receiver": map[string]any{"allowed_disclosure_fields": []string{"summary"}},
	"adapter_constraints": map[string]any{"receiver-sender": map[string]any{
		"max_request_bytes": 65536, "max_response_bytes": 4096, "allowed_route_ids": []string{"submissions-v1"}}},
}

func TestCurrentConvertsTheLoadedSnapshot(t *testing.T) {
	cat := catalog(t)
	s := bundletest.Build(t, "bundle-1", cat, data)
	l := loader(t, s)
	src := &bundle.Source{Loader: l}
	if _, err := src.Current(context.Background()); !errors.Is(err, bundle.ErrNotLoaded) {
		t.Fatalf("before the first load: %v", err)
	}
	if src.ArtifactDigest() != "" {
		t.Fatal("artifact digest before load")
	}
	if err := l.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := execute.AdapterConstraint{MaxRequestBytes: 65536, MaxResponseBytes: 4096, AllowedRouteIDs: []string{"submissions-v1"}}
	if b.BundleID != "bundle-1" || b.ArtifactDigest != s.ArtifactDigest || b.Catalog.CatalogDigest != cat.CatalogDigest ||
		!reflect.DeepEqual(b.ReceiverAllowedFields, []string{"summary"}) || !reflect.DeepEqual(b.AdapterConstraints["receiver-sender"], want) {
		t.Fatalf("bundle %+v", b)
	}
	if src.ArtifactDigest() != s.ArtifactDigest {
		t.Fatal("lease active_version is not the loaded artifact digest")
	}
	again, err := src.Current(context.Background())
	if err != nil || again != b {
		t.Fatalf("same snapshot converted again: %v", err)
	}
}

func TestBundleWithoutAdapterDataIsRefused(t *testing.T) {
	for name, extra := range map[string]map[string]any{
		"no receiver":            {"adapter_constraints": data["adapter_constraints"]},
		"no adapter_constraints": {"receiver": data["receiver"]},
		"bad constraint type":    {"receiver": data["receiver"], "adapter_constraints": map[string]any{"receiver-sender": "x"}},
	} {
		l := loader(t, bundletest.Build(t, "bundle-1", catalog(t), extra))
		if err := l.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := (&bundle.Source{Loader: l}).Current(context.Background()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNilSource(t *testing.T) {
	var s *bundle.Source
	if _, err := s.Current(context.Background()); !errors.Is(err, bundle.ErrNotLoaded) {
		t.Fatal(err)
	}
}
