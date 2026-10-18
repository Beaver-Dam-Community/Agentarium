package gateway

import (
	"context"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/healthlease"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

// BundleStatus is the loaded snapshot and the last load result.
// *policyloader.Loader implements it.
type BundleStatus interface {
	Snapshots
	Status() policyloader.Status
}

// LeaseState is the state of the gateway's own lease (TASK-04 3.5 lease reporting,
// COMMON ControlHealthLease, component = gateway, one source_id per replica):
//
//   - loaded_artifact_digest and active_version: the artifact_digest of the
//     loaded bundle (COMMON names loaded_artifact_digest for bundle loaders,
//     TASK-04 3.5 and TASK-10 3.2 name active_version; both carry it);
//   - active_bundle_revision: the bundle Manifest.Revision;
//   - canonical_version: packages/canonical CanonicalizationVersion;
//   - observed_state: degraded while no bundle is loaded, after a failed
//     load (the previous snapshot stays in use, TASK-10 3.2) or while the
//     database does not answer ping (TASK-04 chapter 3 fact lookup failure); healthy
//     otherwise.
//
// SPEC-QUESTION: TASK-04 asks for the degraded reason in the lease, but
// COMMON allows details only for netpol-collector, so the reason is logged by
// the loader and the request paths, not sent.
func LeaseState(b BundleStatus, ping func(context.Context) error) func(context.Context) healthlease.State {
	return func(ctx context.Context) healthlease.State {
		cv := canonical.CanonicalizationVersion
		st := healthlease.State{ObservedState: healthlease.Healthy, CanonicalVersion: &cv}
		if snap := b.Current(); snap != nil {
			digest, rev := snap.ArtifactDigest(), snap.Revision()
			st.ActiveVersion, st.LoadedArtifactDigest, st.ActiveBundleRevision = &digest, &digest, &rev
		} else {
			st.ObservedState = healthlease.Degraded
		}
		if b.Status().LastError != "" {
			st.ObservedState = healthlease.Degraded
		}
		if ping == nil || ping(ctx) != nil {
			st.ObservedState = healthlease.Degraded
		}
		return st
	}
}
