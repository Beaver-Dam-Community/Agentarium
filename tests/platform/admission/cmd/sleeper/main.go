// Command sleeper is the digest-pinned fixture image for the live admission
// test (TASK-01 7, placement bypass): it does nothing and exits on SIGTERM.
package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
	<-ch
}
