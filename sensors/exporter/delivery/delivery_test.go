package delivery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/acquire"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

func tlsFixture(t *testing.T, h http.Handler) (*httptest.Server, *tls.Config) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	leaf := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{{Scheme: "spiffe", Host: "agentarium.internal", Path: "/ns/agent-observe/sa/audit-writer"}}}
		der, e := x509.CreateCertificate(rand.Reader, cert, parsed, &key.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{leaf(2, x509.ExtKeyUsageServerAuth)}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s, &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{leaf(3, x509.ExtKeyUsageClientAuth)}}
}

func observationID(epoch string, seq uint64) string {
	id, err := canonical.KernelEventID("sensor", epoch, int64(seq))
	if err != nil {
		panic(err)
	}
	return id
}
func normalized(epoch string, seq uint64) ([]byte, error) {
	id, err := canonical.KernelEventID("sensor", epoch, int64(seq))
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`{"source_event_id":%q,"sensor_id":"sensor","source_epoch":%q,"source_sequence":%d}`, id, epoch, seq)), nil
}
func journal(t *testing.T, dir, epoch string, n int) *wal.Journal {
	t.Helper()
	j, err := wal.Open(dir, epoch, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	for i := 0; i < n; i++ {
		if _, err := j.Append(normalized, wal.Checkpoint{}); err != nil {
			t.Fatal(err)
		}
	}
	return j
}
func pump(t *testing.T, j *wal.Journal, h http.Handler) *Pump {
	t.Helper()
	s, tlsConfig := tlsFixture(t, h)
	c, err := batch.NewClient(s.URL, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	p, err := New(Config{Journal: j, Client: c, SourceID: "sensor", Stream: batch.Kernel, RecoveryReason: "wal_segment_corrupt"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type envelope struct {
	ID      string            `json:"batch_id"`
	Epoch   string            `json:"source_epoch"`
	Records []json.RawMessage `json:"records"`
	Ranges  []batch.Range     `json:"sequence_range_abandoned"`
}

func response(t *testing.T, w http.ResponseWriter, raw []byte, duplicate bool) envelope {
	t.Helper()
	var in envelope
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Error(err)
		return in
	}
	for _, gap := range in.Ranges {
		digest, err := canonical.AbandonedRangeDigest("sensor", "kernel", in.Epoch, int64(gap.From), int64(gap.To), gap.Reason)
		if err != nil || digest != gap.Digest {
			t.Errorf("noncanonical range on wire: %v", err)
		}
	}
	accepted := []string{}
	dups := []string{}
	var through uint64
	for _, r := range in.Records {
		var v struct {
			ID  string `json:"source_event_id"`
			Seq uint64 `json:"source_sequence"`
		}
		if err := json.Unmarshal(r, &v); err != nil {
			t.Error(err)
		}
		through = max(through, v.Seq)
		if duplicate {
			dups = append(dups, v.ID)
		} else {
			accepted = append(accepted, v.ID)
		}
	}
	for _, r := range in.Ranges {
		through = max(through, r.To)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"batch_id": in.ID, "accepted_ids": accepted, "duplicate_ids": dups, "rejected": []any{}, "watermarks": []any{map[string]any{"source_epoch": in.Epoch, "acked_through": through}}})
	return in
}
func TestRetryFreezesBytesAndOnlyAckDeletes(t *testing.T) {
	j := journal(t, t.TempDir()+"/spool", "old", 1)
	var original []byte
	calls := 0
	p := pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		calls++
		if calls == 1 {
			original = raw
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		if !bytes.Equal(raw, original) {
			t.Error("retry changed batch bytes")
		}
		response(t, w, raw, true)
	}))
	if _, err := p.Flush(context.Background()); err == nil {
		t.Fatal("lost response accepted")
	}
	w, err := j.Next(100, batch.MaxBytes)
	if err != nil || w.Acked != 0 || len(w.Records) != 1 {
		t.Fatal("WAL changed before ack")
	}
	result, err := p.Flush(context.Background())
	if err != nil || result.Acked != 1 {
		t.Fatalf("retry %+v %v", result, err)
	}
	result, err = p.Flush(context.Background())
	if err != nil || !result.Idle {
		t.Fatalf("not drained %+v %v", result, err)
	}
}
func TestSchemaRejectionSurvivesRestartThenBecomesGap(t *testing.T) {
	dir := t.TempDir() + "/spool"
	j := journal(t, dir, "old", 3)
	p := pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in envelope
		_ = json.NewDecoder(r.Body).Decode(&in)
		_ = json.NewEncoder(w).Encode(map[string]any{"batch_id": in.ID, "accepted_ids": []string{observationID("old", 1), observationID("old", 3)}, "duplicate_ids": []string{}, "rejected": []any{map[string]any{"id": observationID("old", 2), "reason_codes": []string{"SCHEMA_INVALID"}}}, "watermarks": []any{map[string]any{"source_epoch": "old", "acked_through": 1}}})
	}))
	result, err := p.Flush(context.Background())
	if err != nil || result.Acked != 1 || result.Quarantined != 1 {
		t.Fatalf("reject %+v %v", result, err)
	}
	_ = j.Close()
	j = journal(t, dir, "new", 0)
	p = pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		in := response(t, w, raw, true)
		if in.Epoch != "old" || len(in.Records) != 1 || len(in.Ranges) != 1 || in.Ranges[0].From != 2 || in.Ranges[0].To != 2 || in.Ranges[0].Reason != "record_rejected" {
			t.Errorf("invalid replacement %+v", in)
		}
		if bytes.Contains(raw, []byte(observationID("old", 2))) {
			t.Error("retransmitted terminal rejected ID")
		}
	}))
	result, err = p.Flush(context.Background())
	if err != nil || result.Acked != 2 {
		t.Fatalf("gap ack %+v %v", result, err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "rejected-*.json"))
	if len(files) != 1 {
		t.Fatal("quarantine evidence removed")
	}
	raw, err := os.ReadFile(files[0])
	if err != nil || !bytes.Contains(raw, []byte(observationID("old", 2))) {
		t.Fatal("original evidence not retained")
	}
}
func TestPermanentFailuresKeepWAL(t *testing.T) {
	for _, mode := range []string{"auth", "invalid_ack", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			j := journal(t, t.TempDir()+"/spool", "ep", 1)
			p := pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "auth" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				var in envelope
				_ = json.NewDecoder(r.Body).Decode(&in)
				rejected := []any{}
				through := uint64(1)
				if mode == "conflict" {
					through = 0
					rejected = append(rejected, map[string]any{"id": observationID("ep", 1), "reason_codes": []string{"EVENT_ID_CONFLICT"}})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"batch_id": in.ID, "accepted_ids": []string{}, "duplicate_ids": []string{}, "rejected": rejected, "watermarks": []any{map[string]any{"source_epoch": "ep", "acked_through": through}}})
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := p.Run(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("did not stop permanent failure: %v", err)
			}
			w, err := j.Next(100, batch.MaxBytes)
			if err != nil || len(w.Records) != 1 || w.Acked != 0 || w.Rejected[1] {
				t.Fatalf("discarded WAL %+v %v", w, err)
			}
		})
	}
}
func TestRunDrainsBacklogAndCancellationInterruptsBackoff(t *testing.T) {
	t.Run("backlog", func(t *testing.T) {
		j := journal(t, t.TempDir()+"/spool", "ep", 205)
		var mu sync.Mutex
		counts := []int{}
		p := pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			in := response(t, w, raw, false)
			mu.Lock()
			counts = append(counts, len(in.Records))
			mu.Unlock()
		}))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- p.Run(ctx) }()
		deadline := time.After(3 * time.Second)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		drained := false
		for !drained {
			select {
			case <-deadline:
				t.Fatal("backlog did not drain")
			case <-tick.C:
				w, err := j.Next(100, batch.MaxBytes)
				if err != nil {
					t.Fatal(err)
				}
				drained = w.Epoch == ""
			}
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if fmt.Sprint(counts) != "[100 100 5]" {
			t.Fatalf("batch sizes %v", counts)
		}
	})
	t.Run("backoff", func(t *testing.T) {
		j := journal(t, t.TempDir()+"/spool", "ep", 1)
		called := make(chan struct{}, 1)
		p := pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503); called <- struct{}{} }))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- p.Run(ctx) }()
		<-called
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation waited for retry timer")
		}
		pending, err := j.Pending()
		if err != nil || len(pending) != 1 {
			t.Fatal("lost WAL during backoff")
		}
	})
}
func TestEnvelopeSizeSplitsBeforeLimitAndRejectsUnsendableRecord(t *testing.T) {
	for _, tooLarge := range []bool{false, true} {
		t.Run(fmt.Sprint(tooLarge), func(t *testing.T) {
			j := journal(t, t.TempDir()+"/spool", "ep", 0)
			target := batch.MaxBytes/2 - 50
			n := 2
			if tooLarge {
				target = batch.MaxBytes - 20
				n = 1
			}
			for i := 0; i < n; i++ {
				_, err := j.Append(func(epoch string, seq uint64) ([]byte, error) {
					raw, _ := normalized(epoch, seq)
					var fields map[string]any
					_ = json.Unmarshal(raw, &fields)
					fields["padding"] = ""
					raw, _ = json.Marshal(fields)
					fields["padding"] = strings.Repeat("x", target-len(raw))
					return json.Marshal(fields)
				}, wal.Checkpoint{})
				if err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			p := pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				raw, _ := io.ReadAll(r.Body)
				if len(raw) > batch.MaxBytes {
					t.Error("oversized request")
				}
				in := response(t, w, raw, false)
				if len(in.Records) != 1 {
					t.Error("failed to trim envelope")
				}
			}))
			result, err := p.Flush(context.Background())
			if tooLarge {
				if err == nil || calls != 0 {
					t.Fatal("sent oversized first record")
				}
				pending, _ := j.Pending()
				if len(pending) != 1 {
					t.Fatal("lost unsendable record")
				}
			} else if err != nil || result.Acked != 1 {
				t.Fatalf("split %+v %v", result, err)
			}
		})
	}
}

func TestRecoveredReservationSendsGapBeforeWatermarkMoves(t *testing.T) {
	dir := t.TempDir() + "/spool"
	j := journal(t, dir, "old", 2)
	pending, err := j.Pending()
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "wal-*.seg"))
	if err := os.Truncate(files[0], int64(12+len(pending[0].Payload)+5)); err != nil {
		t.Fatal(err)
	}
	j = journal(t, dir, "new", 0)
	damaged, err := filepath.Glob(filepath.Join(dir, "damaged-*.bin"))
	if err != nil || len(damaged) != 1 {
		t.Fatalf("missing pre-delivery damage evidence: %v", err)
	}
	preserved, err := os.ReadFile(damaged[0])
	if err != nil {
		t.Fatal(err)
	}
	p := pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		in := response(t, w, raw, false)
		if in.Epoch != "old" || len(in.Records) != 1 || len(in.Ranges) != 1 || in.Ranges[0].From != 2 || in.Ranges[0].To != 2 || in.Ranges[0].Reason != "wal_segment_corrupt" {
			t.Errorf("recovery gap missing %+v", in)
		}
	}))
	result, err := p.Flush(context.Background())
	if err != nil || result.Acked != 2 {
		t.Fatalf("recovery delivery %+v %v", result, err)
	}
	result, err = p.Flush(context.Background())
	if err != nil || !result.Idle {
		t.Fatalf("recovery not drained %+v %v", result, err)
	}
	after, err := os.ReadFile(damaged[0])
	if err != nil || !bytes.Equal(after, preserved) {
		t.Fatal("committed gap watermark removed original damage evidence")
	}
}

func TestTransientHTTPRetriesSameBatchThenDrains(t *testing.T) {
	j := journal(t, t.TempDir()+"/spool", "ep", 1)
	var mu sync.Mutex
	var bodies [][]byte
	p := pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, raw)
		n := len(bodies)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(503)
			return
		}
		response(t, w, raw, false)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	deadline := time.After(4 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("transient retry did not drain")
		case <-tick.C:
			w, err := j.Next(100, batch.MaxBytes)
			if err != nil {
				t.Fatal(err)
			}
			if w.Epoch != "" {
				continue
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
				t.Fatal("transient retry changed bytes")
			}
			return
		}
	}
}

func TestAcquisitionToWALToMTLSWithLostAck(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "tetragon.log")
	if err := os.WriteFile(live, []byte("first\nfilter\nsecond\n"), 0600); err != nil {
		t.Fatal(err)
	}
	j := journal(t, filepath.Join(dir, "spool"), "ep", 0)
	// This adapter is a contract fixture, not Tetragon event normalization.
	c, err := acquire.New(acquire.Config{Journal: j, LiveFile: live, MaxFiles: 6, MaxLineBytes: 1024, Normalize: func(_ context.Context, raw []byte) (acquire.Prepared, error) {
		if string(raw) == "filter\n" {
			return acquire.Prepared{Excluded: true}, nil
		}
		return acquire.Prepared{Build: normalized}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	cp := j.Checkpoint()
	if cp.Offset != 20 {
		t.Fatalf("input offset %d", cp.Offset)
	}
	var original []byte
	calls := 0
	p := pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		calls++
		if calls == 1 {
			original = raw
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		if !bytes.Equal(original, raw) {
			t.Error("retry changed acquired records")
		}
		in := response(t, w, raw, true)
		if len(in.Records) != 2 {
			t.Error("filtered source got a sequence")
		}
	}))
	if _, err := p.Flush(context.Background()); err == nil {
		t.Fatal("lost ack accepted")
	}
	result, err := p.Flush(context.Background())
	if err != nil || result.Acked != 2 {
		t.Fatalf("pipeline ack %+v %v", result, err)
	}
	if j.Checkpoint() != cp {
		t.Fatal("delivery changed input checkpoint")
	}
	idle, err := c.Step(context.Background())
	if err != nil || !idle.Idle {
		t.Fatalf("re-read already spooled input %+v %v", idle, err)
	}
}
