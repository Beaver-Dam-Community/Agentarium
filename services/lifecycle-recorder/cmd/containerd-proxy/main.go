// Command containerd-proxy is the only container of the lifecycle-recorder
// Pod that mounts the containerd socket (TASK-09 3.6 containerd access boundary). It
// forwards Events/Subscribe, Containers Get/List and CRI ContainerStatus from
// a Pod-local unix socket and denies every other method.
//
//	containerd-proxy --upstream /run/containerd/containerd.sock \
//	  --listen /run/agentarium-containerd/containerd.sock
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Beaver-Dam-Community/Agentarium/services/lifecycle-recorder/ctrdproxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// The process runs as UID 0, GID 65532 with no capabilities (set by the
	// Pod), like the exporter's UID 0. It is already non-dumpable from execve
	// because the image ships /app execute-only
	// (build/docker/containerd-proxy.Dockerfile); this call is the first
	// statement so the setting is confirmed before anything else runs, and the
	// proxy does not start without it (TASK-09 3.6).
	if err := nonDumpable(); err != nil {
		log.Fatal("containerd-proxy: ", err)
	}
	upstream := flag.String("upstream", "/run/containerd/containerd.sock", "containerd socket")
	listen := flag.String("listen", "/run/agentarium-containerd/containerd.sock", "proxy socket shared with the recorder")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	conn, err := grpc.NewClient("unix://"+*upstream, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64<<20)))
	if err != nil {
		log.Fatal("containerd client: ", err)
	}
	defer conn.Close()
	ln, err := ctrdproxy.Listen(*listen)
	if err != nil {
		log.Fatal("proxy socket: ", err)
	}
	srv := ctrdproxy.NewServer(conn)
	go func() {
		<-ctx.Done()
		srv.Stop()
	}()
	log.Printf("containerd-proxy serving %s", *listen)
	if err := srv.Serve(ln); err != nil {
		log.Fatal("containerd-proxy stopped: ", err)
	}
}
