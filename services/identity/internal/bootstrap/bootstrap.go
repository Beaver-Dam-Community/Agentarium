// Package bootstrap implements POST /internal/workload-certificates
// (TASK-03 3.3.2, COMMON "service PKI and identifiers"): a workload proves who it is
// with its projected ServiceAccount token, and the identity service decides
// the SAN from what Kubernetes and identity.registered_workloads say.
package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/issuer"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/pki"
)

// Audience is the projected token audience the identity service accepts.
const Audience = "agentarium-identity"

const (
	extraPodUID  = "authentication.kubernetes.io/pod-uid"
	extraPodName = "authentication.kubernetes.io/pod-name"
	saPrefix     = "system:serviceaccount:"
)

// TokenReview is the part of a TokenReview status this package uses.
type TokenReview struct {
	Authenticated bool
	Audiences     []string
	Username      string
	Extra         map[string][]string
}

// Pod and Node carry the fields checked in TASK-03 3.3.2 steps 2-3.
type Pod struct {
	UID            string
	Namespace      string
	Name           string
	ServiceAccount string
	NodeName       string
	Deleting       bool
}

type Node struct {
	UID    string
	BootID string
}

// ErrNotFound is returned by Cluster when the object does not exist.
var ErrNotFound = errors.New("not found")

// Cluster is what the identity service reads from the Kubernetes API with its
// KSA (tokenreviews.create, pods/nodes get).
type Cluster interface {
	ReviewToken(ctx context.Context, token string, audiences []string) (TokenReview, error)
	GetPod(ctx context.Context, namespace, name string) (Pod, error)
	GetNode(ctx context.Context, name string) (Node, error)
}

// Workload is one identity.registered_workloads row.
type Workload struct {
	Namespace string
	KSA       string
	Role      pki.Role
	Enabled   bool
}

// IssuedRecord is one identity.issued_certificates row.
type IssuedRecord struct {
	Serial    string
	SAN       string
	Namespace string
	KSA       string
	PodUID    string // empty for service certificates unless PodBound
	NodeUID   string
	BootID    string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// podBoundServices are the service workloads whose certificates are bound to
// the Pod they were issued to, although their SAN stays the service SAN. They
// are the lifecycle sources of the COMMON "Lifecycle source authentication and epoch"
// table: lifecycle ingestion checks revoked_at of their certificates on every
// request, so the revoker must be able to revoke them when the Pod is deleted.
// Other service certificates keep pod_uid NULL (TASK-03 3.3.1: they are
// replaced with their Deployment and not checked per request).
var podBoundServices = map[string]bool{
	"agent-sensors/lifecycle-recorder": true,
	"agent-observe/pod-watcher":        true,
}

// PodBound reports whether certificates of the workload record the Pod UID,
// so that the revoker sets revoked_at when that Pod is deleted.
func PodBound(role pki.Role, namespace, ksa string) bool {
	switch role {
	case pki.RoleRuntime, pki.RoleProbe:
		return true
	case pki.RoleService:
		return podBoundServices[namespace+"/"+ksa]
	}
	return false
}

// Store is the identity schema access this package needs.
type Store interface {
	Workload(ctx context.Context, namespace, ksa string) (Workload, bool, error)
	RecordIssued(ctx context.Context, r IssuedRecord) error
}

// Error kinds the HTTP layer maps to status codes.
var (
	// ErrUnauthenticated: the caller is not a live, registered workload.
	ErrUnauthenticated = errors.New("workload not authenticated")
	// ErrBadRequest: the CSR is unusable.
	ErrBadRequest = errors.New("bad certificate request")
	// ErrUnavailable: the Kubernetes API, the CA or the database failed.
	// Issue always wraps one of the three kinds below, so the HTTP layer can
	// pick a reason code per dependency; each still matches ErrUnavailable.
	ErrUnavailable = errors.New("dependency unavailable")
	// ErrClusterUnavailable: TokenReview or a Pod/Node get failed.
	ErrClusterUnavailable = fmt.Errorf("%w: kubernetes api", ErrUnavailable)
	// ErrStoreUnavailable: an identity schema read or write failed.
	ErrStoreUnavailable = fmt.Errorf("%w: state store", ErrUnavailable)
	// ErrIssuerUnavailable: the CA (CAS) did not issue the certificate.
	ErrIssuerUnavailable = fmt.Errorf("%w: certificate authority", ErrUnavailable)
)

// Service issues workload certificates.
type Service struct {
	Cluster Cluster
	Store   Store
	Issuer  issuer.Issuer
	Now     func() time.Time
	NewID   func() string
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) newID() string {
	if s.NewID != nil {
		return s.NewID()
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// Issue runs TASK-03 3.3.2 steps 1-4 and records the certificate before
// returning it. The CSR contributes only its public key.
func (s *Service) Issue(ctx context.Context, token string, csrPEM []byte) (issuer.Certificate, error) {
	if token == "" {
		return issuer.Certificate{}, fmt.Errorf("%w: empty token", ErrUnauthenticated)
	}
	pubDER, err := pki.ParseCSR(csrPEM)
	if err != nil {
		return issuer.Certificate{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}

	// Step 1: TokenReview with audience agentarium-identity.
	tr, err := s.Cluster.ReviewToken(ctx, token, []string{Audience})
	if err != nil {
		return issuer.Certificate{}, fmt.Errorf("%w: token review: %v", ErrClusterUnavailable, err)
	}
	if !tr.Authenticated || !contains(tr.Audiences, Audience) {
		return issuer.Certificate{}, fmt.Errorf("%w: token not authenticated for %s", ErrUnauthenticated, Audience)
	}
	ns, ksa, ok := parseSAUsername(tr.Username)
	if !ok {
		return issuer.Certificate{}, fmt.Errorf("%w: not a service account token", ErrUnauthenticated)
	}
	podUID, ok1 := single(tr.Extra[extraPodUID])
	podName, ok2 := single(tr.Extra[extraPodName])
	if !ok1 || !ok2 {
		return issuer.Certificate{}, fmt.Errorf("%w: token is not bound to exactly one pod", ErrUnauthenticated)
	}

	// Step 2: the Pod named in the token must exist with the same UID,
	// namespace and service account, and the namespace/KSA must be registered.
	pod, err := s.Cluster.GetPod(ctx, ns, podName)
	if errors.Is(err, ErrNotFound) {
		return issuer.Certificate{}, fmt.Errorf("%w: pod %s/%s not found", ErrUnauthenticated, ns, podName)
	}
	if err != nil {
		return issuer.Certificate{}, fmt.Errorf("%w: get pod: %v", ErrClusterUnavailable, err)
	}
	if pod.UID != podUID || pod.Namespace != ns || pod.ServiceAccount != ksa || pod.Deleting {
		return issuer.Certificate{}, fmt.Errorf("%w: pod does not match the token", ErrUnauthenticated)
	}
	wl, found, err := s.Store.Workload(ctx, ns, ksa)
	if err != nil {
		return issuer.Certificate{}, fmt.Errorf("%w: lookup workload: %v", ErrStoreUnavailable, err)
	}
	if !found || !wl.Enabled {
		return issuer.Certificate{}, fmt.Errorf("%w: %s/%s is not a registered workload", ErrUnauthenticated, ns, ksa)
	}

	// Step 3: the Node the Pod runs on, with its UID and boot ID.
	if pod.NodeName == "" {
		return issuer.Certificate{}, fmt.Errorf("%w: pod is not scheduled", ErrUnauthenticated)
	}
	node, err := s.Cluster.GetNode(ctx, pod.NodeName)
	if errors.Is(err, ErrNotFound) {
		return issuer.Certificate{}, fmt.Errorf("%w: node %s not found", ErrUnauthenticated, pod.NodeName)
	}
	if err != nil {
		return issuer.Certificate{}, fmt.Errorf("%w: get node: %v", ErrClusterUnavailable, err)
	}
	if node.UID == "" || node.BootID == "" {
		return issuer.Certificate{}, fmt.Errorf("%w: node has no uid or boot id", ErrUnauthenticated)
	}

	// Step 4: the server-decided SAN and EKU.
	prof, err := pki.ProfileFor(wl.Role, ns, ksa, pod.UID)
	if err != nil {
		return issuer.Certificate{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	cert, err := s.Issuer.Issue(ctx, issuer.Request{
		RequestID:    s.newID(),
		PublicKeyDER: pubDER,
		SAN:          prof.SAN,
		ClientOnly:   prof.ClientOnly,
		Lifetime:     prof.Lifetime,
	})
	if err != nil {
		return issuer.Certificate{}, fmt.Errorf("%w: %v", ErrIssuerUnavailable, err)
	}

	rec := IssuedRecord{
		Serial: cert.Serial, SAN: prof.SAN, Namespace: ns, KSA: ksa,
		NodeUID: node.UID, BootID: node.BootID, IssuedAt: s.now(), ExpiresAt: cert.NotAfter,
	}
	// The Pod was matched against the token in step 2, so its UID is the
	// one the revoker sees when the Pod is deleted.
	if PodBound(wl.Role, ns, ksa) {
		rec.PodUID = pod.UID
	}
	// The certificate is returned only after the record is committed, so a
	// certificate the gateway and coordinator cannot look up is never handed out.
	if err := s.Store.RecordIssued(ctx, rec); err != nil {
		return issuer.Certificate{}, fmt.Errorf("%w: record issued certificate: %v", ErrStoreUnavailable, err)
	}
	return cert, nil
}

func parseSAUsername(u string) (ns, ksa string, ok bool) {
	rest, found := strings.CutPrefix(u, saPrefix)
	if !found {
		return "", "", false
	}
	ns, ksa, found = strings.Cut(rest, ":")
	if !found || ns == "" || ksa == "" || strings.Contains(ksa, ":") {
		return "", "", false
	}
	return ns, ksa, true
}

func single(v []string) (string, bool) {
	if len(v) != 1 || v[0] == "" {
		return "", false
	}
	return v[0], true
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
