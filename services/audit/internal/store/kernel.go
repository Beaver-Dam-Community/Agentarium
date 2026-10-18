package store

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ValidateKernelConfiguration enables the kernel route only for an installed
// tetragon binding whose source ID equals its service SAN, with node CIDRs.
func (a *Authorizer) ValidateKernelConfiguration(nodeCIDRs []netip.Prefix) error {
	b, ok := a.bindings[ingest.KernelSourceSAN]
	if !ok {
		return errors.New("kernel source binding required")
	}
	if b.SourceID != "spiffe://agentarium.internal/ns/"+b.Namespace+"/sa/"+b.KSA || len(b.Scopes) != 0 {
		return errors.New("kernel source must equal registered service SAN")
	}
	if len(nodeCIDRs) == 0 {
		return errors.New("kernel ingest requires node CIDRs")
	}
	return nil
}

// ResolveKernel checks the registered principal and the restricted certificate
// and current-boot helpers, like the lifecycle runtime source.
func (a *Authorizer) ResolveKernel(ctx context.Context, cert *x509.Certificate) (ingest.LifecycleSource, error) {
	var source ingest.LifecycleSource
	if cert == nil || cert.SerialNumber == nil || len(cert.URIs) != 1 || cert.URIs[0].String() != ingest.KernelSourceSAN {
		return source, ingest.ErrForbidden
	}
	san := ingest.KernelSourceSAN
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
	if identity.Namespace != "agent-sensors" || identity.Ksa != "tetragon" || !identity.NodeUid.Valid || identity.CertificateBootID == "" {
		return source, ingest.ErrForbidden
	}
	current, err := q.LifecycleCurrentBoot(ctx, auditdb.LifecycleCurrentBootParams{NodeUid: identity.NodeUid, BootID: identity.CertificateBootID})
	if err != nil {
		return source, classify(err)
	}
	if !current {
		return source, ingest.ErrForbidden
	}
	return ingest.LifecycleSource{SourceID: san, Kind: "runtime", NodeUID: uuid.UUID(identity.NodeUid.Bytes).String(), BootID: identity.CertificateBootID}, nil
}

// ValidateKernel applies envelope policy only: the runtime epoch encoding.
func (a *Authorizer) ValidateKernel(_ context.Context, source ingest.LifecycleSource, b ingest.KernelEnvelope) error {
	if _, ok := a.bindings[source.SourceID]; !ok || source.SourceID != ingest.KernelSourceSAN || source.Kind != "runtime" {
		return ingest.ErrForbidden
	}
	if !runtimeEpoch.MatchString(b.Epoch) {
		return ingest.ErrSchema
	}
	return nil
}

// IngestKernel calls the six-argument SQL contract and returns only after a
// validated result and a successful COMMIT. SQL repeats every source check.
func (s Store) IngestKernel(ctx context.Context, source ingest.LifecycleSource, raw []byte) (json.RawMessage, error) {
	if s.WriterVersion == "" || s.WriterEpoch == "" || source.CertificateSerial == "" || source.ExactSAN == "" || source.SourceID != source.ExactSAN {
		return nil, errors.New("kernel identity/configuration unavailable")
	}
	b, err := ingest.DecodeKernelEnvelope(raw)
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	ack, err := auditdb.New(tx).IngestKernelBatch(ctx, auditdb.IngestKernelBatchParams{SourceID: source.SourceID, Batch: raw, CertificateSerial: source.CertificateSerial, ExactSan: source.ExactSAN, WriterVersion: s.WriterVersion, WriterEpoch: s.WriterEpoch})
	if err != nil {
		return nil, classifyLifecycle(err)
	}
	if err := ingest.ValidateKernelAck(ack, b); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return ack, nil
}
