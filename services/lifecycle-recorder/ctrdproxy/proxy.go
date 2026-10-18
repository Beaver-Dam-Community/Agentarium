// Package ctrdproxy is the containerd-proxy of the lifecycle-recorder Pod
// (TASK-09 3.6 containerd access boundary). It is the only container that holds the
// raw containerd socket. It serves four read methods on a Pod-local unix
// socket, rebuilds each upstream request, reduces each response to the fields
// the recorder mapping uses, and rejects every other method and service with
// PermissionDenied before anything reaches containerd.
package ctrdproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"strings"
	"syscall"

	eventtypes "github.com/containerd/containerd/api/events"
	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	eventsapi "github.com/containerd/containerd/api/services/events/v1"
	"github.com/containerd/containerd/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// The only methods the proxy forwards.
const (
	MethodSubscribe       = "/containerd.services.events.v1.Events/Subscribe"
	MethodGet             = "/containerd.services.containers.v1.Containers/Get"
	MethodList            = "/containerd.services.containers.v1.Containers/List"
	MethodContainerStatus = "/runtime.v1.RuntimeService/ContainerStatus"
)

var allowed = map[string]bool{MethodSubscribe: true, MethodGet: true, MethodList: true, MethodContainerStatus: true}

// Namespace and TaskFilter are the only containerd namespace and event filter
// the recorder uses (services/lifecycle-recorder/recorder).
const (
	Namespace  = "k8s.io"
	TaskFilter = `topic~="/tasks/"`
)

// Labels and OCI annotations kept in container records: the recorder mapping
// reads exactly these (TASK-09 3.6 runtime record mapping).
var (
	keptLabels      = []string{"io.kubernetes.pod.uid", "io.kubernetes.pod.namespace", "io.kubernetes.pod.name", "io.kubernetes.container.name"}
	keptAnnotations = []string{"io.kubernetes.container.restartCount", "io.kubernetes.cri.container-type"}
)

var errDenied = status.Error(codes.PermissionDenied, "method not allowed by containerd-proxy")

type proxy struct {
	eventsapi.UnimplementedEventsServer
	containersapi.UnimplementedContainersServer
	cri.UnimplementedRuntimeServiceServer
	upstream *grpc.ClientConn
}

// NewServer returns the proxy gRPC server forwarding to upstream (a client of
// the real containerd socket). It registers no reflection or health service.
func NewServer(upstream *grpc.ClientConn) *grpc.Server {
	p := &proxy{upstream: upstream}
	s := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if !allowed[info.FullMethod] {
				return nil, errDenied
			}
			return h(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			if !allowed[info.FullMethod] {
				return errDenied
			}
			return h(srv, ss)
		}),
		grpc.UnknownServiceHandler(func(any, grpc.ServerStream) error { return errDenied }),
	)
	eventsapi.RegisterEventsServer(s, p)
	containersapi.RegisterContainersServer(s, p)
	cri.RegisterRuntimeServiceServer(s, p)
	return s
}

// Listen creates the proxy socket with mode 0660 so that only the socket
// owner and its group (the recorder's gid) can connect. A stale socket left
// by a previous container is removed; any other file there is an error.
func Listen(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, errors.New("proxy socket path exists and is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o117)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// upstreamCtx is a fresh outgoing context: caller metadata is never forwarded.
func upstreamCtx(ctx context.Context) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("containerd-namespace", Namespace))
}

func requireNamespace(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get("containerd-namespace"); len(v) != 1 || v[0] != Namespace {
		return status.Error(codes.PermissionDenied, "only containerd namespace k8s.io is allowed")
	}
	return nil
}

func (p *proxy) Subscribe(req *eventsapi.SubscribeRequest, stream eventsapi.Events_SubscribeServer) error {
	if err := requireNamespace(stream.Context()); err != nil {
		return err
	}
	if f := req.GetFilters(); len(f) != 1 || f[0] != TaskFilter {
		return status.Error(codes.InvalidArgument, "only the task event filter is allowed")
	}
	up, err := eventsapi.NewEventsClient(p.upstream).Subscribe(upstreamCtx(stream.Context()), &eventsapi.SubscribeRequest{Filters: []string{TaskFilter}})
	if err != nil {
		return err
	}
	// Tell the recorder the upstream subscription is open before it lists.
	if err := stream.SendHeader(metadata.MD{}); err != nil {
		return err
	}
	for {
		env, err := up.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		out, err := reduceEvent(env)
		if err != nil {
			return err
		}
		if out == nil {
			continue
		}
		if err := stream.Send(out); err != nil {
			return err
		}
	}
}

// reduceEvent forwards only the four lifecycle task events with the fields
// the recorder maps (container_id and process id); bundle paths, rootfs
// mounts, IO paths, pids and exit details stay in the proxy. Other task
// events (exec added/started, OOM, pause, checkpoint) are dropped.
func reduceEvent(env *types.Envelope) (*types.Envelope, error) {
	if env.GetEvent() == nil {
		return nil, nil
	}
	var msg proto.Message
	name := env.GetEvent().GetTypeUrl()
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:] // anypb form "types.googleapis.com/<full name>"
	}
	switch name {
	case typeName(&eventtypes.TaskCreate{}):
		msg = &eventtypes.TaskCreate{}
	case typeName(&eventtypes.TaskStart{}):
		msg = &eventtypes.TaskStart{}
	case typeName(&eventtypes.TaskExit{}):
		msg = &eventtypes.TaskExit{}
	case typeName(&eventtypes.TaskDelete{}):
		msg = &eventtypes.TaskDelete{}
	default:
		return nil, nil
	}
	if err := proto.Unmarshal(env.GetEvent().GetValue(), msg); err != nil {
		return nil, status.Error(codes.Internal, "undecodable task event")
	}
	var min proto.Message
	switch e := msg.(type) {
	case *eventtypes.TaskCreate:
		min = &eventtypes.TaskCreate{ContainerID: e.GetContainerID()}
	case *eventtypes.TaskStart:
		min = &eventtypes.TaskStart{ContainerID: e.GetContainerID()}
	case *eventtypes.TaskExit:
		min = &eventtypes.TaskExit{ContainerID: e.GetContainerID(), ID: e.GetID()}
	case *eventtypes.TaskDelete:
		min = &eventtypes.TaskDelete{ContainerID: e.GetContainerID(), ID: e.GetID()}
	}
	b, err := proto.Marshal(min)
	if err != nil {
		return nil, err
	}
	return &types.Envelope{Timestamp: env.GetTimestamp(), Namespace: env.GetNamespace(), Topic: env.GetTopic(),
		Event: &anypb.Any{TypeUrl: env.GetEvent().GetTypeUrl(), Value: b}}, nil
}

// typeName is containerd's typeurl for an event: the full proto name.
func typeName(m proto.Message) string { return string(m.ProtoReflect().Descriptor().FullName()) }

func (p *proxy) Get(ctx context.Context, req *containersapi.GetContainerRequest) (*containersapi.GetContainerResponse, error) {
	if err := requireNamespace(ctx); err != nil {
		return nil, err
	}
	if req.GetID() == "" {
		return nil, status.Error(codes.InvalidArgument, "container id is required")
	}
	resp, err := containersapi.NewContainersClient(p.upstream).Get(upstreamCtx(ctx), &containersapi.GetContainerRequest{ID: req.GetID()})
	if err != nil {
		return nil, err
	}
	c, err := reduce(resp.GetContainer())
	if err != nil {
		return nil, err
	}
	return &containersapi.GetContainerResponse{Container: c}, nil
}

func (p *proxy) List(ctx context.Context, req *containersapi.ListContainersRequest) (*containersapi.ListContainersResponse, error) {
	if err := requireNamespace(ctx); err != nil {
		return nil, err
	}
	if len(req.GetFilters()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "list filters are not allowed")
	}
	resp, err := containersapi.NewContainersClient(p.upstream).List(upstreamCtx(ctx), &containersapi.ListContainersRequest{})
	if err != nil {
		return nil, err
	}
	out := &containersapi.ListContainersResponse{}
	for _, c := range resp.GetContainers() {
		r, err := reduce(c)
		if err != nil {
			return nil, err
		}
		out.Containers = append(out.Containers, r)
	}
	return out, nil
}

func (p *proxy) ContainerStatus(ctx context.Context, req *cri.ContainerStatusRequest) (*cri.ContainerStatusResponse, error) {
	if req.GetVerbose() {
		return nil, status.Error(codes.InvalidArgument, "verbose container status is not allowed")
	}
	if req.GetContainerId() == "" {
		return nil, status.Error(codes.InvalidArgument, "container id is required")
	}
	resp, err := cri.NewRuntimeServiceClient(p.upstream).ContainerStatus(upstreamCtx(ctx), &cri.ContainerStatusRequest{ContainerId: req.GetContainerId()})
	if err != nil {
		return nil, err
	}
	return &cri.ContainerStatusResponse{Status: &cri.ContainerStatus{Id: resp.GetStatus().GetId(), ImageId: resp.GetStatus().GetImageId()}}, nil
}

// reduce keeps the container ID, the four CRI labels, and from the OCI spec
// only linux.cgroupsPath and the two CRI annotations. Env, mounts, process
// arguments, runtime options and extensions of other Pods' containers are
// dropped.
func reduce(c *containersapi.Container) (*containersapi.Container, error) {
	out := &containersapi.Container{ID: c.GetID()}
	for _, k := range keptLabels {
		if v, ok := c.GetLabels()[k]; ok {
			if out.Labels == nil {
				out.Labels = map[string]string{}
			}
			out.Labels[k] = v
		}
	}
	spec := c.GetSpec()
	if spec == nil || len(spec.GetValue()) == 0 {
		return out, nil
	}
	var oci struct {
		Annotations map[string]string `json:"annotations"`
		Linux       *struct {
			CgroupsPath string `json:"cgroupsPath"`
		} `json:"linux"`
	}
	if err := json.Unmarshal(spec.GetValue(), &oci); err != nil {
		// No spec rather than an error: the recorder still identifies the
		// Pod from the labels and marks the record runtime_metadata_partial.
		return out, nil
	}
	min := map[string]any{}
	if oci.Linux != nil {
		min["linux"] = map[string]string{"cgroupsPath": oci.Linux.CgroupsPath}
	}
	ann := map[string]string{}
	for _, k := range keptAnnotations {
		if v, ok := oci.Annotations[k]; ok {
			ann[k] = v
		}
	}
	if len(ann) > 0 {
		min["annotations"] = ann
	}
	b, err := json.Marshal(min)
	if err != nil {
		return nil, err
	}
	out.Spec = &anypb.Any{TypeUrl: spec.GetTypeUrl(), Value: b}
	return out, nil
}
