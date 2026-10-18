package ctrdproxy_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eventtypes "github.com/containerd/containerd/api/events"
	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	eventsapi "github.com/containerd/containerd/api/services/events/v1"
	namespacesapi "github.com/containerd/containerd/api/services/namespaces/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/Beaver-Dam-Community/Agentarium/services/lifecycle-recorder/ctrdproxy"
	"github.com/Beaver-Dam-Community/Agentarium/services/lifecycle-recorder/internal/ctrdtest"
	"github.com/Beaver-Dam-Community/Agentarium/services/lifecycle-recorder/recorder"
)

const (
	cid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pod = "11111111-2222-4333-8444-555555555555"
)

// setup runs the fixture containerd on one unix socket and the proxy on
// another, and returns a client connection to the proxy socket.
func setup(t *testing.T) (*ctrdtest.Fake, *grpc.ClientConn, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ctrdproxy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	fake := ctrdtest.New()
	c := ctrdtest.PodContainer(cid, pod, "main", "kubepods-pod11111111.slice:cri-containerd:"+cid, false)
	// A real record also carries env, args, mounts and runtime details of the
	// Pod; the proxy must not pass them on.
	spec := map[string]any{"linux": map[string]any{"cgroupsPath": "kubepods-pod11111111.slice:cri-containerd:" + cid},
		"annotations": map[string]string{"io.kubernetes.container.restartCount": "2", "io.kubernetes.cri.container-type": "container", "io.kubernetes.cri.sandbox-id": "s"},
		"process":     map[string]any{"env": []string{"API_TOKEN=secret-value"}, "args": []string{"/bin/agent"}},
		"mounts":      []map[string]string{{"destination": "/var/run/secrets/kubernetes.io/serviceaccount"}}}
	raw, _ := json.Marshal(spec)
	c.Spec = &anypb.Any{TypeUrl: c.Spec.TypeUrl, Value: raw}
	c.Labels["io.kubernetes.pod.extra"] = "x"
	c.Image = "registry.example/agent:1"
	c.Extensions = map[string]*anypb.Any{"ext": {TypeUrl: "x", Value: []byte("secret-value")}}
	fake.Containers[cid] = c
	fake.Order = []string{cid}
	upSock := fake.Serve(t, dir)
	up, err := grpc.NewClient("unix://"+upSock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { up.Close() })
	proxySock := filepath.Join(dir, "proxy.sock")
	ln, err := ctrdproxy.Listen(proxySock)
	if err != nil {
		t.Fatal(err)
	}
	srv := ctrdproxy.NewServer(up)
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("unix://"+proxySock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return fake, conn, proxySock
}

func nsCtx(t *testing.T, ns string) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return metadata.AppendToOutgoingContext(ctx, "containerd-namespace", ns)
}

func calls(f *ctrdtest.Fake) []string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return append([]string(nil), f.Calls...)
}

func TestProxyConstantsMatchRecorder(t *testing.T) {
	if ctrdproxy.Namespace != recorder.Namespace || ctrdproxy.TaskFilter != recorder.TaskFilter {
		t.Fatal("proxy namespace/filter differ from the recorder's")
	}
}

func TestSocketMode(t *testing.T) {
	_, _, sock := setup(t)
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("proxy socket mode %v", fi.Mode().Perm())
	}
	// A non-socket file at the path is not replaced.
	plain := filepath.Join(filepath.Dir(sock), "plain")
	os.WriteFile(plain, []byte("x"), 0o600)
	if _, err := ctrdproxy.Listen(plain); err == nil {
		t.Fatal("listen replaced a regular file")
	}
}

func TestAllowedMethodsAreForwardedAndReduced(t *testing.T) {
	fake, conn, _ := setup(t)
	ctx := nsCtx(t, "k8s.io")

	got, err := containersapi.NewContainersClient(conn).Get(ctx, &containersapi.GetContainerRequest{ID: cid})
	if err != nil {
		t.Fatal(err)
	}
	list, err := containersapi.NewContainersClient(conn).List(ctx, &containersapi.ListContainersRequest{})
	if err != nil || len(list.Containers) != 1 {
		t.Fatalf("list %v %v", list, err)
	}
	for _, c := range []*containersapi.Container{got.Container, list.Containers[0]} {
		if c.ID != cid || c.Image != "" || c.Extensions != nil || c.Runtime != nil || c.Labels["io.kubernetes.pod.extra"] != "" || c.Labels["io.kubernetes.pod.uid"] != pod || c.Labels["io.kubernetes.container.name"] != "main" {
			t.Fatalf("container not reduced: %v", c)
		}
		var spec map[string]any
		if err := json.Unmarshal(c.Spec.Value, &spec); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(spec)
		want := `{"annotations":{"io.kubernetes.container.restartCount":"2","io.kubernetes.cri.container-type":"container"},"linux":{"cgroupsPath":"kubepods-pod11111111.slice:cri-containerd:` + cid + `"}}`
		if string(b) != want || strings.Contains(string(b), "secret-value") {
			t.Fatalf("spec %s", b)
		}
	}
	// The recorder's own decoding still works on the reduced record.
	src := recorder.GRPCSource{Conn: conn}
	rc, err := src.Container(context.Background(), cid)
	if err != nil || rc.PodUID != pod || rc.RestartCount == nil || *rc.RestartCount != 2 || rc.CgroupsPath == "" {
		t.Fatalf("recorder view %+v %v", rc, err)
	}

	st, err := cri.NewRuntimeServiceClient(conn).ContainerStatus(ctx, &cri.ContainerStatusRequest{ContainerId: cid})
	if err != nil || st.Status.Id != cid || !strings.HasPrefix(st.Status.ImageId, "sha256:") {
		t.Fatalf("status %v %v", st, err)
	}

	sub, err := eventsapi.NewEventsClient(conn).Subscribe(ctx, &eventsapi.SubscribeRequest{Filters: []string{ctrdproxy.TaskFilter}})
	if err != nil {
		t.Fatal(err)
	}
	var stream chan *types.Envelope
	select {
	case stream = <-fake.Streams:
	case <-time.After(5 * time.Second):
		t.Fatal("subscribe did not reach containerd")
	}
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskStart{ContainerID: cid, Pid: 7}, "/tasks/start", time.Now())
	env, err := sub.Recv()
	if err != nil || env.Topic != "/tasks/start" {
		t.Fatalf("event %v %v", env, err)
	}
	fake.Mu.Lock()
	violations := fake.Violations
	fake.Mu.Unlock()
	if len(violations) != 0 {
		t.Fatalf("upstream contract violations: %v", violations)
	}
}

func TestOtherMethodsAreDeniedWithoutReachingContainerd(t *testing.T) {
	fake, conn, _ := setup(t)
	ctx := nsCtx(t, "k8s.io")
	containers := containersapi.NewContainersClient(conn)
	tasks := tasksapi.NewTasksClient(conn)
	runtime := cri.NewRuntimeServiceClient(conn)
	denied := map[string]func() error{
		"Containers/Create": func() error {
			_, err := containers.Create(ctx, &containersapi.CreateContainerRequest{Container: &containersapi.Container{ID: "x"}})
			return err
		},
		"Containers/Update": func() error {
			_, err := containers.Update(ctx, &containersapi.UpdateContainerRequest{Container: &containersapi.Container{ID: cid}})
			return err
		},
		"Containers/Delete": func() error {
			_, err := containers.Delete(ctx, &containersapi.DeleteContainerRequest{ID: cid})
			return err
		},
		"Containers/ListStream": func() error {
			s, err := containers.ListStream(ctx, &containersapi.ListContainersRequest{})
			if err != nil {
				return err
			}
			_, err = s.Recv()
			return err
		},
		"Tasks/Create": func() error {
			_, err := tasks.Create(ctx, &tasksapi.CreateTaskRequest{ContainerID: cid})
			return err
		},
		"Tasks/Exec": func() error {
			_, err := tasks.Exec(ctx, &tasksapi.ExecProcessRequest{ContainerID: cid, ExecID: "sh"})
			return err
		},
		"Tasks/Kill": func() error {
			_, err := tasks.Kill(ctx, &tasksapi.KillRequest{ContainerID: cid, Signal: 9})
			return err
		},
		"Tasks/Delete": func() error {
			_, err := tasks.Delete(ctx, &tasksapi.DeleteTaskRequest{ContainerID: cid})
			return err
		},
		"Events/Publish": func() error {
			_, err := eventsapi.NewEventsClient(conn).Publish(ctx, &eventsapi.PublishRequest{Topic: "/tasks/exit"})
			return err
		},
		"Namespaces/Create": func() error {
			_, err := namespacesapi.NewNamespacesClient(conn).Create(ctx, &namespacesapi.CreateNamespaceRequest{Namespace: &namespacesapi.Namespace{Name: "evil"}})
			return err
		},
		"Namespaces/List": func() error {
			_, err := namespacesapi.NewNamespacesClient(conn).List(ctx, &namespacesapi.ListNamespacesRequest{})
			return err
		},
		"CRI/ExecSync": func() error {
			_, err := runtime.ExecSync(ctx, &cri.ExecSyncRequest{ContainerId: cid, Cmd: []string{"id"}})
			return err
		},
		"CRI/Exec": func() error {
			_, err := runtime.Exec(ctx, &cri.ExecRequest{ContainerId: cid, Cmd: []string{"sh"}})
			return err
		},
		"CRI/CreateContainer": func() error {
			_, err := runtime.CreateContainer(ctx, &cri.CreateContainerRequest{PodSandboxId: "s"})
			return err
		},
		"CRI/RemoveContainer": func() error {
			_, err := runtime.RemoveContainer(ctx, &cri.RemoveContainerRequest{ContainerId: cid})
			return err
		},
		"CRI/ListContainers": func() error {
			_, err := runtime.ListContainers(ctx, &cri.ListContainersRequest{})
			return err
		},
		"reflection": func() error {
			s, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo")
			if err != nil {
				return err
			}
			s.CloseSend()
			return s.RecvMsg(&emptypb.Empty{})
		},
		"health": func() error {
			return conn.Invoke(ctx, "/grpc.health.v1.Health/Check", &emptypb.Empty{}, &emptypb.Empty{})
		},
	}
	for name, call := range denied {
		if code := status.Code(call()); code != codes.PermissionDenied {
			t.Errorf("%s: code %v, want PermissionDenied", name, code)
		}
	}
	if c := calls(fake); len(c) != 0 {
		t.Fatalf("denied calls reached containerd: %v", c)
	}
}

func TestAllowedMethodsRejectOutOfContractRequests(t *testing.T) {
	fake, conn, _ := setup(t)
	containers := containersapi.NewContainersClient(conn)
	cases := map[string]struct {
		call func() error
		code codes.Code
	}{
		"Get in another namespace": {func() error {
			_, err := containers.Get(nsCtx(t, "moby"), &containersapi.GetContainerRequest{ID: cid})
			return err
		}, codes.PermissionDenied},
		"List without namespace": {func() error {
			_, err := containers.List(context.Background(), &containersapi.ListContainersRequest{})
			return err
		}, codes.PermissionDenied},
		"List with filters": {func() error {
			_, err := containers.List(nsCtx(t, "k8s.io"), &containersapi.ListContainersRequest{Filters: []string{"id==x"}})
			return err
		}, codes.InvalidArgument},
		"Subscribe to all topics": {func() error {
			s, err := eventsapi.NewEventsClient(conn).Subscribe(nsCtx(t, "k8s.io"), &eventsapi.SubscribeRequest{})
			if err != nil {
				return err
			}
			_, err = s.Recv()
			return err
		}, codes.InvalidArgument},
		"Subscribe in another namespace": {func() error {
			s, err := eventsapi.NewEventsClient(conn).Subscribe(nsCtx(t, "moby"), &eventsapi.SubscribeRequest{Filters: []string{ctrdproxy.TaskFilter}})
			if err != nil {
				return err
			}
			_, err = s.Recv()
			return err
		}, codes.PermissionDenied},
		"verbose ContainerStatus": {func() error {
			_, err := cri.NewRuntimeServiceClient(conn).ContainerStatus(nsCtx(t, "k8s.io"), &cri.ContainerStatusRequest{ContainerId: cid, Verbose: true})
			return err
		}, codes.InvalidArgument},
	}
	for name, c := range cases {
		if code := status.Code(c.call()); code != c.code {
			t.Errorf("%s: code %v, want %v", name, code, c.code)
		}
	}
	if c := calls(fake); len(c) != 0 {
		t.Fatalf("rejected calls reached containerd: %v", c)
	}
}

// Subscribe answers with headers once upstream is open, forwards only the four
// lifecycle task events and strips them to container_id and id.
func TestSubscribeHeadersAndReducedEvents(t *testing.T) {
	fake, conn, _ := setup(t)
	sub, err := eventsapi.NewEventsClient(conn).Subscribe(nsCtx(t, "k8s.io"), &eventsapi.SubscribeRequest{Filters: []string{ctrdproxy.TaskFilter}})
	if err != nil {
		t.Fatal(err)
	}
	headers := make(chan error, 1)
	go func() { _, err := sub.Header(); headers <- err }()
	var stream chan *types.Envelope
	select {
	case stream = <-fake.Streams:
	case <-time.After(5 * time.Second):
		t.Fatal("subscribe did not reach containerd")
	}
	select {
	case err := <-headers:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no response header before the first event")
	}
	at := time.Now()
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskExecAdded{ContainerID: cid, ExecID: "sh"}, "/tasks/exec-added", at)
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskOOM{ContainerID: cid}, "/tasks/oom", at)
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskCreate{ContainerID: cid, Bundle: "/run/containerd/io.containerd.runtime.v2.task/k8s.io/" + cid, Pid: 42,
		Rootfs: []*types.Mount{{Type: "overlay", Source: "overlay", Options: []string{"lowerdir=/secret"}}}, IO: &eventtypes.TaskIO{Stdout: "/run/fifo/stdout"}}, "/tasks/create", at)
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskExit{ContainerID: cid, ID: cid, Pid: 42, ExitStatus: 137}, "/tasks/exit", at)
	for _, want := range []proto.Message{&eventtypes.TaskCreate{ContainerID: cid}, &eventtypes.TaskExit{ContainerID: cid, ID: cid}} {
		env, err := sub.Recv()
		if err != nil {
			t.Fatal(err)
		}
		got, err := anypb.UnmarshalNew(env.Event, proto.UnmarshalOptions{})
		if err != nil || !proto.Equal(got, want) || env.Namespace != "k8s.io" || !env.Timestamp.AsTime().Equal(at) {
			t.Fatalf("event %v (%v), want %v", got, err, want)
		}
	}
}

// A container whose OCI spec is not JSON is returned without the spec.
func TestNonJSONSpecIsDropped(t *testing.T) {
	fake, conn, _ := setup(t)
	fake.Mu.Lock()
	fake.Containers[cid].Spec = &anypb.Any{TypeUrl: "x", Value: []byte{0xff, 0x00}}
	fake.Mu.Unlock()
	got, err := containersapi.NewContainersClient(conn).Get(nsCtx(t, "k8s.io"), &containersapi.GetContainerRequest{ID: cid})
	if err != nil || got.Container.Spec != nil || got.Container.Labels["io.kubernetes.pod.uid"] != pod {
		t.Fatalf("%v %v", got, err)
	}
}
