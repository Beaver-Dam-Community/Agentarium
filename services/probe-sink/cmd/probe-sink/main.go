// Command probe-sink is the agent-targets target of the TASK-10 3.2 tcp
// answer probe. It listens on --listen (default :8443) and accepts plain TCP
// connections that carry no data.
//
// SPEC-QUESTION: TASK-06 lists probe-sink -> workload-identity, so the sink
// may later be expected to terminate TLS; the tcp probe only needs
// connect and close (TASK-10 3.2), so no certificate is used here.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Beaver-Dam-Community/Agentarium/services/probe-sink/internal/sink"
)

func main() {
	listen := flag.String("listen", ":8443", "TCP listen address")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Error("listen", "error", err.Error())
		os.Exit(1)
	}
	logger.Info("probe sink listening", "address", l.Addr().String())
	if err := sink.Serve(ctx, l, logger); err != nil {
		logger.Error("probe-sink exited", "error", err.Error())
		os.Exit(1)
	}
}
