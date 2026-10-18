package store

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const lifecycleRecorder = "spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder"
const podWatcher = "spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher"

var runtimeEpoch = regexp.MustCompile(`^[0-9a-f]{128}$`)
var watcherEpoch = regexp.MustCompile(`^[0-9a-f]{32}_[1-9][0-9]{0,15}$`)

// ValidateLifecycleConfiguration enables only explicitly installed sources. The
// writer separately acquires its persistent instance/restart epoch before serving.
func (a *Authorizer) ValidateLifecycleConfiguration(nodeCIDRs []netip.Prefix) error {
	found := false
	for _, b := range a.bindings {
		if b.SourceID != lifecycleRecorder && b.SourceID != podWatcher {
			continue
		}
		found = true
		if b.SourceID != "spiffe://agentarium.internal/ns/"+b.Namespace+"/sa/"+b.KSA {
			return errors.New("lifecycle source must equal registered service SAN")
		}
		if b.SourceID == lifecycleRecorder && len(nodeCIDRs) == 0 {
			return errors.New("lifecycle recorder requires node CIDRs")
		}
		if b.SourceID == podWatcher {
			if len(b.Scopes) == 0 {
				return errors.New("watcher requires explicit scopes")
			}
			seen := map[string]bool{}
			for _, scope := range b.Scopes {
				if scope == "" || len(scope) > 16384 || seen[scope] {
					return errors.New("invalid lifecycle scope configuration")
				}
				seen[scope] = true
			}
		}
	}
	if !found {
		return errors.New("lifecycle source binding required")
	}
	return nil
}

// ResolveLifecycle is called only with a verified mTLS leaf. Registered principal
// checks use the existing authorizer; certificate/node reads use restricted
// owner functions, never issued_certificates or health base-table SELECT.
func (a *Authorizer) ResolveLifecycle(ctx context.Context, cert *x509.Certificate, _ netip.Addr) (ingest.LifecycleSource, error) {
	var source ingest.LifecycleSource
	if cert == nil || cert.SerialNumber == nil || len(cert.URIs) != 1 {
		return source, ingest.ErrForbidden
	}
	san := cert.URIs[0].String()
	if san != lifecycleRecorder && san != podWatcher {
		return source, ingest.ErrForbidden
	}
	if err := a.Authorize(ctx, san, san); err != nil {
		return source, err
	}
	q := auditdb.New(a.Pool)
	identity, err := q.LifecycleSourceCertificate(ctx, auditdb.LifecycleSourceCertificateParams{CertificateSerial: hex.EncodeToString(cert.SerialNumber.Bytes()), ExactSan: san})
	if errors.Is(err, pgx.ErrNoRows) {
		return source, ingest.ErrForbidden
	}
	if err != nil {
		return source, classify(err)
	}
	ns, ksa, _ := ingest.ParseServiceSAN(san)
	if identity.Namespace != ns || identity.Ksa != ksa {
		return source, ingest.ErrForbidden
	}
	source = ingest.LifecycleSource{SourceID: san, Kind: "pod_watcher"}
	if san == lifecycleRecorder {
		if !identity.NodeUid.Valid || identity.CertificateBootID == "" {
			return source, ingest.ErrForbidden
		}
		current, err := q.LifecycleCurrentBoot(ctx, auditdb.LifecycleCurrentBootParams{NodeUid: identity.NodeUid, BootID: identity.CertificateBootID})
		if err != nil {
			return source, classify(err)
		}
		if !current {
			return source, ingest.ErrForbidden
		}
		source.Kind = "runtime"
		source.NodeUID = uuid.UUID(identity.NodeUid.Bytes).String()
		source.BootID = identity.CertificateBootID
	}
	return source, nil
}

// ValidateLifecycle applies source-specific envelope policy. Record validation,
// historical boot provenance, grants and individual rejection remain in SQL.
// Empty Epoch is used only by the authenticated checkpoint GET scope check.
func (a *Authorizer) ValidateLifecycle(_ context.Context, source ingest.LifecycleSource, b ingest.LifecycleEnvelope) error {
	binding, exists := a.bindings[source.SourceID]
	if !exists {
		return ingest.ErrForbidden
	}
	switch source.Kind {
	case "runtime":
		if source.SourceID != lifecycleRecorder || !runtimeEpoch.MatchString(b.Epoch) || b.Scope != "" || b.Cursor != nil {
			return ingest.ErrSchema
		}
	case "pod_watcher":
		if source.SourceID != podWatcher {
			return ingest.ErrForbidden
		}
		allowed := false
		for _, scope := range binding.Scopes {
			if b.Scope == scope {
				allowed = true
				break
			}
		}
		if !allowed {
			return ingest.ErrForbidden
		}
		if b.Epoch != "" {
			if !watcherEpoch.MatchString(b.Epoch) {
				return ingest.ErrSchema
			}
			count, err := strconv.ParseInt(strings.Split(b.Epoch, "_")[1], 10, 64)
			if err != nil || count > 9007199254740991 {
				return ingest.ErrSchema
			}
		}
	default:
		return ingest.ErrForbidden
	}
	return nil
}
