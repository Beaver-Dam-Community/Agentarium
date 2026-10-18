package export

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLeaseRunRejectsUnsafeRenewInterval(t *testing.T) {
	l := &PGLease{Holder: "x"}
	for _, every := range []time.Duration{0, -time.Second, 25 * time.Second, time.Minute} {
		if err := l.Run(context.Background(), []string{"gcs"}, every, nil); !errors.Is(err, ErrRenewInterval) {
			t.Fatalf("%s accepted: %v", every, err)
		}
	}
}
