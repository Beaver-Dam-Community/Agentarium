// Package recorder is the TASK-09 3.6 runtime lifecycle recorder: it
// subscribes to containerd task events of namespace k8s.io, reads container
// records for cgroupsPath and CRI labels, and turns them into LifecycleRecords
// (mapping_version 1, PR #207).
package recorder

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	eventsapi "github.com/containerd/containerd/api/services/events/v1"
	"github.com/containerd/containerd/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// Namespace is the containerd namespace kubelet's CRI plugin uses.
const Namespace = "k8s.io"

// TaskFilter selects task lifecycle events (TASK-09 3.6 step 1).
const TaskFilter = `topic~="/tasks/"`

// Container is the part of a containerd container record the mapping uses.
type Container struct {
	ID, CgroupsPath               string
	PodUID, PodNamespace, PodName string
	ContainerName                 string
	RestartCount                  *int32
	Sandbox                       bool
}

// Source is the containerd/CRI boundary of the recorder.
type Source interface {
	Subscribe(ctx context.Context) (func() (*types.Envelope, error), error)
	Container(ctx context.Context, id string) (Container, error)
	Containers(ctx context.Context) ([]Container, error)
	ImageID(ctx context.Context, id string) (string, error)
}

// GRPCSource talks to containerd's gRPC API and the CRI runtime service on
// the same socket.
type GRPCSource struct {
	Conn *grpc.ClientConn
}

func nsCtx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "containerd-namespace", Namespace)
}

func (s GRPCSource) Subscribe(ctx context.Context) (func() (*types.Envelope, error), error) {
	stream, err := eventsapi.NewEventsClient(s.Conn).Subscribe(nsCtx(ctx), &eventsapi.SubscribeRequest{Filters: []string{TaskFilter}})
	if err != nil {
		return nil, err
	}
	// The containerd-proxy sends response headers once its upstream
	// subscription is open (TASK-09 3.6); list only after that.
	if _, err := stream.Header(); err != nil {
		return nil, err
	}
	return stream.Recv, nil
}

// CRI label and annotation keys (TASK-09 3.6; their exact names are a Q0 item).
const (
	labelPodUID       = "io.kubernetes.pod.uid"
	labelPodNamespace = "io.kubernetes.pod.namespace"
	labelPodName      = "io.kubernetes.pod.name"
	labelContainer    = "io.kubernetes.container.name"
	annoRestartCount  = "io.kubernetes.container.restartCount"
	annoContainerType = "io.kubernetes.cri.container-type"
)

func fromRecord(c *containersapi.Container) (Container, error) {
	out := Container{ID: c.GetID(), PodUID: c.GetLabels()[labelPodUID], PodNamespace: c.GetLabels()[labelPodNamespace], PodName: c.GetLabels()[labelPodName], ContainerName: c.GetLabels()[labelContainer]}
	if spec := c.GetSpec(); spec != nil && len(spec.GetValue()) > 0 {
		var oci struct {
			Annotations map[string]string `json:"annotations"`
			Linux       *struct {
				CgroupsPath string `json:"cgroupsPath"`
			} `json:"linux"`
		}
		if err := json.Unmarshal(spec.GetValue(), &oci); err != nil {
			return out, errors.New("container OCI spec is not JSON")
		}
		if oci.Linux != nil {
			out.CgroupsPath = oci.Linux.CgroupsPath
		}
		out.Sandbox = oci.Annotations[annoContainerType] == "sandbox"
		if v, ok := oci.Annotations[annoRestartCount]; ok {
			if n, err := strconv.ParseInt(v, 10, 32); err == nil && n >= 0 {
				r := int32(n)
				out.RestartCount = &r
			}
		}
	}
	return out, nil
}

func (s GRPCSource) Container(ctx context.Context, id string) (Container, error) {
	resp, err := containersapi.NewContainersClient(s.Conn).Get(nsCtx(ctx), &containersapi.GetContainerRequest{ID: id})
	if err != nil {
		return Container{}, err
	}
	return fromRecord(resp.GetContainer())
}

func (s GRPCSource) Containers(ctx context.Context) ([]Container, error) {
	resp, err := containersapi.NewContainersClient(s.Conn).List(nsCtx(ctx), &containersapi.ListContainersRequest{})
	if err != nil {
		return nil, err
	}
	var out []Container
	for _, c := range resp.GetContainers() {
		r, err := fromRecord(c)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// ImageID is CRI ContainerStatus.image_id (the image config digest). Sandbox
// containers are not CRI containers and return an error.
func (s GRPCSource) ImageID(ctx context.Context, id string) (string, error) {
	resp, err := cri.NewRuntimeServiceClient(s.Conn).ContainerStatus(ctx, &cri.ContainerStatusRequest{ContainerId: id})
	if err != nil {
		return "", err
	}
	if v := resp.GetStatus().GetImageId(); v != "" {
		return v, nil
	}
	return "", errors.New("CRI status has no image_id")
}
