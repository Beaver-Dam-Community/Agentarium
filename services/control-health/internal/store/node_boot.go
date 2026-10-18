package store

import (
	"context"
	"errors"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/store/healthdb"
	"github.com/google/uuid"
)

// NodeFacts is an authoritative current Node UID/boot and its pool's Q0 result
// from the trusted environment lock. None of these values may be taken from a
// lease, annotation, or caller-supplied installation profile. A Q0 result that
// was not run, incomplete or missing is unsupported with StartupMeasurement
// not_measured; guarded is only valid when measured.
type NodeFacts struct {
	NodeUID            string
	BootID             string
	StartupCapture     string
	StartupMeasurement string
}

// Lock startup_capture measurement values (TASK-16 3.1).
const (
	Measured    = "measured"
	NotMeasured = "not_measured"
)

// NodeFactsSource must obtain a fresh current Kubernetes node/boot and resolve
// that node pool's Q0 result from the trusted environment lock. The production
// adapter is KubeNodeFacts. Nil means fail closed for every new boot.
type NodeFactsSource interface {
	Current(context.Context, string) (NodeFacts, error)
}

func (s *Store) bootstrapNode(ctx context.Context, q *healthdb.Queries, cert healthdb.CertificateRow, lease health.Lease) (healthdb.HealthNodeBootGeneration, error) {
	var empty healthdb.HealthNodeBootGeneration
	if s.NodeFacts == nil || lease.Component != "node-sensors" || lease.SensorGeneration == nil || *lease.SensorGeneration != 1 || !cert.NodeUid.Valid || !cert.BootID.Valid {
		return empty, health.ErrForbidden
	}
	nodeID := uuid.UUID(cert.NodeUid.Bytes).String()
	// No row exists to lock on a node's first report. Serialize the bootstrap
	// path by node UID; hash collisions only cause extra serialization.
	if err := q.SetNodeBootstrapLockTimeout(ctx); err != nil {
		return empty, err
	}
	if err := q.LockNodeBootstrap(ctx, nodeID); err != nil {
		return empty, err
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	facts, err := s.NodeFacts.Current(call, nodeID)
	cancel()
	if err != nil {
		return empty, errors.New("current node facts unavailable")
	}
	if facts.NodeUID != nodeID || facts.BootID != cert.BootID.String || facts.BootID == "" ||
		(facts.StartupCapture != health.StartupGuarded && facts.StartupCapture != health.StartupUnsupported) ||
		(facts.StartupMeasurement != Measured && facts.StartupMeasurement != NotMeasured) ||
		(facts.StartupCapture == health.StartupGuarded && facts.StartupMeasurement != Measured) {
		return empty, health.ErrForbidden
	}
	rows, err := q.NodeBootHistory(ctx, cert.NodeUid)
	if err != nil {
		return empty, err
	}
	currentCount := 0
	var matching *healthdb.HealthNodeBootGeneration
	for i := range rows {
		if rows[i].State != "retired" {
			currentCount++
		}
		if rows[i].BootID == facts.BootID {
			matching = &rows[i]
		}
	}
	if currentCount > 1 {
		return empty, errors.New("ambiguous current node boot")
	}
	if matching != nil {
		// Never resurrect historical boots, even if a broken facts adapter reports
		// one as current. Concurrent first reports may find the winner's new row.
		if matching.State == "retired" || matching.StartupCapture != facts.StartupCapture || matching.StartupCaptureMeasurement != facts.StartupMeasurement {
			return empty, health.ErrForbidden
		}
		return *matching, nil
	}
	// A dangling lease for an unknown boot is an inconsistent installation, not
	// a first report. Refuse it instead of crossing into hold creation after
	// taking node-row locks (COMMON requires holds before node rows).
	dangling, err := q.HasBootLeases(ctx, healthdb.HasBootLeasesParams{NodeUid: cert.NodeUid, BootID: cert.BootID})
	if err != nil {
		return empty, err
	}
	if dangling {
		return empty, errors.New("lease exists without node boot")
	}
	if err := q.RetireNodeBoots(ctx, cert.NodeUid); err != nil {
		return empty, err
	}
	return q.InsertPreparingNodeBoot(ctx, healthdb.InsertPreparingNodeBootParams{NodeUid: cert.NodeUid, BootID: facts.BootID, StartupCapture: facts.StartupCapture, StartupCaptureMeasurement: facts.StartupMeasurement})
}
