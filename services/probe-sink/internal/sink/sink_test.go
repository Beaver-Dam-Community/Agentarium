package sink

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// A probe runner connects and closes; the sink closes its side as well, so
// the client's socket reaches CLOSE (it sees EOF after its own FIN).
func TestServeAcceptsAndClosesAfterPeer(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	for i := 0; i < 3; i++ {
		c, err := net.DialTimeout("tcp4", l.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := c.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatalf("sink did not close after the peer: %d %v", n, err)
		}
		c.Close()
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
