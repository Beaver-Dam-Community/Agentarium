// Command worker is the session-dedicated worker (/app/bin/agent-worker).
// The supervisor execs it once per session with no arguments, a minimal
// environment and its IPC socket as fd 3 (COMMON session-dedicated worker contract).
// It is not meant to be started by hand.
package main

import (
	"fmt"
	"os"

	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/ipc"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/isolation"
	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/worker"
)

// ipcFD is the first ExtraFiles descriptor.
const ipcFD = 3

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "agent-worker takes no arguments")
		os.Exit(2)
	}
	f := os.NewFile(ipcFD, "ipc")
	if f == nil {
		fmt.Fprintln(os.Stderr, "agent-worker: no IPC descriptor")
		os.Exit(2)
	}
	conn := ipc.New(f)
	defer conn.Close()
	outcome, err := worker.Run(conn, isolation.Apply, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-worker:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "agent-worker finished:", outcome)
}
