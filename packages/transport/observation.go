package transport

import (
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// Peer address kinds (COMMON AdapterObservation peer_addr_kind).
const (
	PeerServiceVIP = "service_vip"
	PeerEndpoint   = "endpoint"
	PeerExternal   = "external"
)

// Observation is the COMMON AdapterObservation. The adapter transport recorder
// fills it inside the adapter process; every optional field is sent as an
// explicit null. process_exec_id is never part of it (TASK-10 adds it from the
// kernel side).
type Observation struct {
	AttemptID         string     `json:"attempt_id"`
	LocalAddr         *string    `json:"local_addr"`
	LocalPort         *int       `json:"local_port"`
	PeerAddr          *string    `json:"peer_addr"`
	PeerPort          *int       `json:"peer_port"`
	NetnsInode        *uint64    `json:"netns_inode"`
	DialedAddr        *string    `json:"dialed_addr"`
	PeerAddrKind      *string    `json:"peer_addr_kind"`
	PodUID            *string    `json:"pod_uid"`
	ConnectStartedAt  *time.Time `json:"connect_started_at"`
	SendStartedAt     *time.Time `json:"send_started_at"`
	SendFinishedAt    *time.Time `json:"send_finished_at"`
	ResponseAt        *time.Time `json:"response_at"`
	ProviderRequestID *string    `json:"provider_request_id"`
	K8sAuditID        *string    `json:"k8s_audit_id"`
	WireBodyDigest    *string    `json:"wire_body_digest"`
}

// NetnsInode returns the inode of /proc/self/ns/net, the network namespace
// part of the kernel connection key (TASK-05 3.4). It is nil where the link
// does not exist (non-Linux test hosts).
func NetnsInode() *uint64 {
	fi, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	ino := uint64(st.Ino)
	return &ino
}

// peerKind classifies RemoteAddr (TASK-05 3.4). A target whose origin host is a
// cluster Service name (".svc" or ".svc.cluster.local") resolves to the
// Service ClusterIP, so RemoteAddr equal to the dialed ClusterIP is
// service_vip and any other address (socket LB translated it) is endpoint.
// Everything else is external. Which of the two Dataplane V2 reports is a Q0
// measurement for TASK-10, so the value is an input, not a conclusion.
func peerKind(host string, dialed, peer net.IP) string {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if strings.HasSuffix(h, ".svc") || strings.HasSuffix(h, ".svc.cluster.local") {
		if dialed != nil && peer != nil && dialed.Equal(peer) {
			return PeerServiceVIP
		}
		return PeerEndpoint
	}
	return PeerExternal
}

func ptr[T any](v T) *T { return &v }
