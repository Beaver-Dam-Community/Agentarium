// Package sink is the TASK-10 3.2 tcp answer probe target (agent-targets
// probe-sink, TCP 8443 in the TASK-06 allow table). A probe runner connects
// and closes; the sink accepts, waits for the peer's close (bounded) and
// closes its side, so the runner's socket passes ESTABLISHED and reaches
// CLOSE. It reads and writes no data and needs no credential.
package sink

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// HoldTimeout bounds one connection.
const HoldTimeout = 5 * time.Second

// MaxConnections bounds concurrent connections (one runner per node and
// probe Namespace connects once a minute).
const MaxConnections = 256

// Serve accepts on l until ctx ends.
func Serve(ctx context.Context, l net.Listener, log *slog.Logger) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	slots := make(chan struct{}, MaxConnections)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			log.Warn("connection limit reached", "remote", c.RemoteAddr().String())
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			hold(c)
		}()
	}
}

func hold(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(HoldTimeout))
	// Discard anything until the peer closes or the deadline passes.
	_, _ = io.Copy(io.Discard, io.LimitReader(c, 4096))
}
