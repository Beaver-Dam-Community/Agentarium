// Package bundle is the execute.BundleSource of the adapters (TASK-05 3.4
// bundle loading): the snapshot packages/policyloader loaded and verified from
// the environment's desired_bundle row (the same loader as the gateway, no
// OPA evaluation), turned into the data the adapter preflight reads:
// data.catalog, data.receiver.allowed_disclosure_fields and
// data.adapter_constraints.
package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

// ErrNotLoaded means no bundle has been loaded yet; the engine leaves the
// execution received (nothing reserved).
var ErrNotLoaded = errors.New("bundle: no policy bundle loaded")

// Snapshots is the part of *policyloader.Loader this package reads.
type Snapshots interface {
	Current() *policyloader.Snapshot
}

// Source converts the loader's current snapshot once per snapshot.
type Source struct {
	Loader Snapshots

	mu     sync.Mutex
	snap   *policyloader.Snapshot
	bundle *execute.Bundle
}

var _ execute.BundleSource = (*Source)(nil)

// Current returns the loaded bundle. The returned value is shared and must
// not be modified.
func (s *Source) Current(context.Context) (*execute.Bundle, error) {
	if s == nil || s.Loader == nil {
		return nil, ErrNotLoaded
	}
	snap := s.Loader.Current()
	if snap == nil {
		return nil, ErrNotLoaded
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap == s.snap {
		return s.bundle, nil
	}
	b, err := FromSnapshot(snap)
	if err != nil {
		return nil, err
	}
	s.snap, s.bundle = snap, b
	return b, nil
}

// ArtifactDigest is the artifact_digest of the loaded bundle, "" before the
// first load. It is the adapter lease's active_version.
func (s *Source) ArtifactDigest() string {
	if s == nil || s.Loader == nil {
		return ""
	}
	if snap := s.Loader.Current(); snap != nil {
		return snap.ArtifactDigest()
	}
	return ""
}

// policyData is the bundle data the adapters read besides data.catalog.
type policyData struct {
	Receiver *struct {
		AllowedDisclosureFields []string `json:"allowed_disclosure_fields"`
	} `json:"receiver"`
	AdapterConstraints map[string]execute.AdapterConstraint `json:"adapter_constraints"`
}

// FromSnapshot builds the execute.Bundle of one verified snapshot. A bundle
// without data.receiver or data.adapter_constraints is refused: packages/bundles
// always writes both, so their absence is a malformed artifact.
func FromSnapshot(snap *policyloader.Snapshot) (*execute.Bundle, error) {
	cat, err := snap.Catalog()
	if err != nil {
		return nil, fmt.Errorf("bundle: data.catalog: %w", err)
	}
	data, err := snap.Data()
	if err != nil {
		return nil, fmt.Errorf("bundle: data: %w", err)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var d policyData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("bundle: data.receiver/adapter_constraints: %w", err)
	}
	if d.Receiver == nil || d.Receiver.AllowedDisclosureFields == nil || d.AdapterConstraints == nil {
		return nil, errors.New("bundle: data.receiver.allowed_disclosure_fields and data.adapter_constraints are required")
	}
	return &execute.Bundle{
		BundleID:              snap.BundleID(),
		ArtifactDigest:        snap.ArtifactDigest(),
		Catalog:               cat,
		ReceiverAllowedFields: d.Receiver.AllowedDisclosureFields,
		AdapterConstraints:    d.AdapterConstraints,
	}, nil
}
