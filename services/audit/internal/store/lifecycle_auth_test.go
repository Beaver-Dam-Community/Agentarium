package store

import (
	"context"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"net/netip"
	"strings"
	"testing"
)

func TestLifecycleInstallationAndScopePolicy(t *testing.T) {
	bindings := []SourceBinding{{SourceID: podWatcher, Namespace: "agent-observe", KSA: "pod-watcher", Principal: "watcher", Scopes: []string{"namespace/agent-exec"}}, {SourceID: lifecycleRecorder, Namespace: "agent-sensors", KSA: "lifecycle-recorder", Principal: "recorder"}}
	a, err := NewAuthorizer(nil, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if a.ValidateLifecycleConfiguration(nil) == nil {
		t.Fatal("recorder enabled without node CIDRs")
	}
	if err := a.ValidateLifecycleConfiguration([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := ingest.LifecycleSource{SourceID: podWatcher, Kind: "pod_watcher"}
	b := ingest.LifecycleEnvelope{Scope: "namespace/agent-exec", Epoch: strings.Repeat("a", 32) + "_1"}
	if err := a.ValidateLifecycle(ctx, s, b); err != nil {
		t.Fatal(err)
	}
	b.Scope = "namespace/forbidden"
	if a.ValidateLifecycle(ctx, s, b) == nil {
		t.Fatal("unknown scope accepted")
	}
	b.Scope = "namespace/agent-exec"
	b.Epoch = strings.Repeat("a", 32) + "_9007199254740992"
	if a.ValidateLifecycle(ctx, s, b) == nil {
		t.Fatal("overflow watcher counter")
	}
	b.Epoch = ""
	if err := a.ValidateLifecycle(ctx, s, b); err != nil {
		t.Fatalf("GET scope: %v", err)
	}
	s = ingest.LifecycleSource{SourceID: lifecycleRecorder, Kind: "runtime"}
	b = ingest.LifecycleEnvelope{Epoch: strings.Repeat("a", 128)}
	if err := a.ValidateLifecycle(ctx, s, b); err != nil {
		t.Fatal(err)
	}
	b.Scope = "namespace/agent-exec"
	if a.ValidateLifecycle(ctx, s, b) == nil {
		t.Fatal("runtime watcher scope accepted")
	}
	a, _ = NewAuthorizer(nil, []SourceBinding{{SourceID: podWatcher, Namespace: "agent-observe", KSA: "pod-watcher", Principal: "watcher"}})
	if a.ValidateLifecycleConfiguration(nil) == nil {
		t.Fatal("watcher enabled without scope allowlist")
	}
}
