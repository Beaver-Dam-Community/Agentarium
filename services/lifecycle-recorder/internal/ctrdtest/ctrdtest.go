// Package ctrdtest is a containerd/CRI gRPC fixture for recorder tests. It
// enforces the k8s.io namespace metadata and the task filter.
package ctrdtest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	eventsapi "github.com/containerd/containerd/api/services/events/v1"
	"github.com/containerd/containerd/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
	"net"
)

const Namespace = "k8s.io"
const TaskFilter = `topic~="/tasks/"`

// fakeContainerd enforces the namespace metadata and task filter the
// recorder must use, and serves Events, Containers and CRI ContainerStatus.
type Fake struct {
	eventsapi.UnimplementedEventsServer
	containersapi.UnimplementedContainersServer
	cri.UnimplementedRuntimeServiceServer
	Mu         sync.Mutex
	Containers map[string]*containersapi.Container
	Streams    chan chan *types.Envelope
	Violations []string
	// Order lists container IDs in List order; Sandbox marks IDs without a
	// CRI ContainerStatus.
	Order   []string
	Sandbox map[string]bool
	// Calls lists every full method name that reached the fixture, including
	// methods of services it does not implement.
	Calls []string
}

func (f *Fake) called(method string) {
	f.Mu.Lock()
	f.Calls = append(f.Calls, method)
	f.Mu.Unlock()
}

func ns(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get("containerd-namespace"); len(v) == 1 {
		return v[0]
	}
	return ""
}

func (f *Fake) bad(s string) {
	f.Mu.Lock()
	f.Violations = append(f.Violations, s)
	f.Mu.Unlock()
}

func (f *Fake) Subscribe(req *eventsapi.SubscribeRequest, stream eventsapi.Events_SubscribeServer) error {
	if ns(stream.Context()) != Namespace || len(req.GetFilters()) != 1 || req.GetFilters()[0] != TaskFilter {
		f.bad(fmt.Sprintf("subscribe ns=%q filters=%v", ns(stream.Context()), req.GetFilters()))
		return status.Error(codes.InvalidArgument, "namespace and task filter required")
	}
	ch := make(chan *types.Envelope, 16)
	f.Streams <- ch
	// Like containerd-proxy, signal that the subscription is registered.
	if err := stream.SendHeader(metadata.MD{}); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case env, ok := <-ch:
			if !ok {
				return status.Error(codes.Unavailable, "stream closed")
			}
			if err := stream.Send(env); err != nil {
				return err
			}
		}
	}
}

func (f *Fake) Get(ctx context.Context, req *containersapi.GetContainerRequest) (*containersapi.GetContainerResponse, error) {
	if ns(ctx) != Namespace {
		f.bad("get without namespace")
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	c, ok := f.Containers[req.GetID()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no container")
	}
	return &containersapi.GetContainerResponse{Container: proto.Clone(c).(*containersapi.Container)}, nil
}

func (f *Fake) List(ctx context.Context, _ *containersapi.ListContainersRequest) (*containersapi.ListContainersResponse, error) {
	if ns(ctx) != Namespace {
		f.bad("list without namespace")
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	var out []*containersapi.Container
	for _, id := range f.Order {
		if c, ok := f.Containers[id]; ok {
			out = append(out, proto.Clone(c).(*containersapi.Container))
		}
	}
	return &containersapi.ListContainersResponse{Containers: out}, nil
}

func (f *Fake) ContainerStatus(_ context.Context, req *cri.ContainerStatusRequest) (*cri.ContainerStatusResponse, error) {
	if f.Sandbox[req.GetContainerId()] {
		return nil, status.Error(codes.NotFound, "sandbox is not a CRI container")
	}
	return &cri.ContainerStatusResponse{Status: &cri.ContainerStatus{Id: req.GetContainerId(), ImageId: "sha256:" + strings.Repeat("9", 64)}}, nil
}

func OCISpec(cgroupsPath string, annotations map[string]string) *anypb.Any {
	b, _ := json.Marshal(map[string]any{"linux": map[string]any{"cgroupsPath": cgroupsPath}, "annotations": annotations})
	return &anypb.Any{TypeUrl: "types.containerd.io/opencontainers/runtime-spec/1/Spec", Value: b}
}

func PodContainer(id, pod, name, cgroupsPath string, sandbox bool) *containersapi.Container {
	ann := map[string]string{"io.kubernetes.container.restartCount": "0"}
	labels := map[string]string{"io.kubernetes.pod.uid": pod, "io.kubernetes.pod.namespace": "agent-exec", "io.kubernetes.pod.name": "pod-" + pod[:4]}
	if sandbox {
		ann = map[string]string{"io.kubernetes.cri.container-type": "sandbox"}
	} else {
		labels["io.kubernetes.container.name"] = name
	}
	return &containersapi.Container{ID: id, Labels: labels, Spec: OCISpec(cgroupsPath, ann)}
}

func Envelope(t *testing.T, msg proto.Message, topic string, at time.Time) *types.Envelope {
	a, err := anypb.New(msg)
	if err != nil {
		t.Fatal(err)
	}
	// containerd's typeurl names events by full proto name, without a host.
	a.TypeUrl = string(msg.ProtoReflect().Descriptor().FullName())
	return &types.Envelope{Timestamp: timestamppb.New(at), Namespace: Namespace, Topic: topic, Event: a}
}

// Serve starts the fixture on a unix socket and returns its path.
func (f *Fake) Serve(t *testing.T, dir string) string {
	t.Helper()
	path := dir + "/containerd.sock"
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			f.called(info.FullMethod)
			return h(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			f.called(info.FullMethod)
			return h(srv, ss)
		}),
		grpc.UnknownServiceHandler(func(_ any, ss grpc.ServerStream) error {
			m, _ := grpc.MethodFromServerStream(ss)
			f.called(m)
			return status.Error(codes.Unimplemented, "not served by the fixture")
		}),
	)
	eventsapi.RegisterEventsServer(g, f)
	containersapi.RegisterContainersServer(g, f)
	cri.RegisterRuntimeServiceServer(g, f)
	go g.Serve(ln)
	t.Cleanup(g.Stop)
	return path
}

// New returns an empty fixture.
func New() *Fake {
	return &Fake{Streams: make(chan chan *types.Envelope, 4), Containers: map[string]*containersapi.Container{}, Sandbox: map[string]bool{}}
}
