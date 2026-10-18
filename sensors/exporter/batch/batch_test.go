package batch

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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

const batchID = "00000000-0000-4000-8000-000000000001"
const event1 = "5a2eca02-144c-53e0-bb3e-23552eb3343d"
const event2 = "805f55f6-26b7-54b3-b362-721861348ddb"

func record(id string, seq uint64) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"source_event_id":%q,"sensor_id":"sensor","source_epoch":"boot_instance","source_sequence":%d}`, id, seq))
}
func input() Input {
	return Input{Stream: Kernel, SourceID: "sensor", Epoch: "boot_instance", BatchID: batchID, Records: []json.RawMessage{record(event1, 1), record(event2, 2)}}
}
func goodResponse() response {
	return response{BatchID: batchID, Accepted: []string{event1, event2}, Duplicates: []string{}, Rejected: []Rejection{}, Watermarks: []watermark{{"boot_instance", 2}}}
}
func raw(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func mustBatch(t *testing.T, in Input) *Batch {
	t.Helper()
	b, e := New(in)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestBatchDigestAndImmutability(t *testing.T) {
	in := input()
	b := mustBatch(t, in)
	before := b.Bytes()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(before, &fields); err != nil {
		t.Fatal(err)
	}
	var digest string
	if err := json.Unmarshal(fields["batch_digest"], &digest); err != nil {
		t.Fatal(err)
	}
	want, e := canonical.BatchDigest(before)
	if e != nil || digest != want {
		t.Fatalf("digest=%s want=%s err=%v", digest, want, e)
	}
	in.Records[0][0] = 'x'
	in.Records = nil
	copyBytes := b.Bytes()
	copyBytes[0] = 'x'
	if !bytes.Equal(before, b.Bytes()) {
		t.Fatal("input or output mutation changed batch")
	}
	if _, ok := fields["source_id"]; ok {
		t.Fatal("source identity leaked into envelope")
	}
}

func TestBatchRejectsInvalidInput(t *testing.T) {
	for name, change := range map[string]func(*Input){
		"stream": func(i *Input) { i.Stream = "other" },
		"id":     func(i *Input) { i.BatchID = "bad" },
		"empty":  func(i *Input) { i.Records = nil },
		"wrong namespace": func(i *Input) {
			id, err := canonical.LifecycleEventID("sensor", "boot_instance", 1)
			if err != nil {
				t.Fatal(err)
			}
			i.Records[0] = record(id, 1)
		},
		"different source":   func(i *Input) { i.SourceID = "other" },
		"different epoch":    func(i *Input) { i.Epoch = "next" },
		"skipped sequence":   func(i *Input) { i.Records[1] = record(event2, 3) },
		"duplicate sequence": func(i *Input) { i.Records[1] = record(event2, 1) },
		"duplicate id":       func(i *Input) { i.Records[1] = record(event1, 2) },
		"already acked":      func(i *Input) { i.PreviousAck = 1 },
		"unsafe integer":     func(i *Input) { i.Records[1] = record(event2, maxSequence+1) },
		"duplicate JSON key": func(i *Input) {
			i.Records[0] = append(i.Records[0][:len(i.Records[0])-1], []byte(`,"source_sequence":1}`)...)
		},
		"null": func(i *Input) { i.Records[0] = json.RawMessage(`null`) },
		"null sequence": func(i *Input) {
			i.Records[0] = bytes.ReplaceAll(i.Records[0], []byte(`"source_sequence":1`), []byte(`"source_sequence":null`))
		},
		"kernel cursor": func(i *Input) { i.Cursor = &Cursor{"namespace/agent-exec", "1", 0} },
		"body bound": func(i *Input) {
			i.Records[0] = json.RawMessage(fmt.Sprintf(`{"source_event_id":%q,"sensor_id":"sensor","source_epoch":"boot_instance","source_sequence":1,"padding":%q}`, event1, strings.Repeat("a", MaxBytes)))
		},
		"record count": func(i *Input) { i.Records = make([]json.RawMessage, 101) },
	} {
		t.Run(name, func(t *testing.T) {
			in := input()
			change(&in)
			if _, e := New(in); e == nil {
				t.Fatal("accepted invalid batch")
			}
		})
	}
}

func TestResponseValidation(t *testing.T) {
	b := mustBatch(t, input())
	for name, change := range map[string]func(*response){
		"batch id":              func(r *response) { r.BatchID = event1 },
		"other epoch":           func(r *response) { r.Watermarks[0].Epoch = "other" },
		"missing watermark":     func(r *response) { r.Watermarks = []watermark{} },
		"multiple watermarks":   func(r *response) { r.Watermarks = append(r.Watermarks, r.Watermarks[0]) },
		"unsafe watermark":      func(r *response) { r.Watermarks[0].Through = maxSequence + 1 },
		"unknown accepted":      func(r *response) { r.Accepted[0] = batchID },
		"duplicate accepted":    func(r *response) { r.Duplicates = []string{event1} },
		"unconfirmed below ack": func(r *response) { r.Accepted = []string{event1} },
		"rejection below ack": func(r *response) {
			r.Accepted = []string{event1}
			r.Rejected = []Rejection{{event2, []string{"SCHEMA_INVALID"}}}
		},
		"rejection without reason": func(r *response) {
			r.Accepted = []string{event1}
			r.Watermarks[0].Through = 1
			r.Rejected = []Rejection{{event2, []string{}}}
		},
		"checkpoint on kernel": func(r *response) { r.Checkpoint = &Checkpoint{"namespace/agent-exec", "1", 1} },
	} {
		t.Run(name, func(t *testing.T) {
			r := goodResponse()
			change(&r)
			if _, e := b.validate(raw(t, r)); e == nil {
				t.Fatal("accepted unsafe ack")
			}
		})
	}
	r := goodResponse()
	r.Accepted = []string{event1}
	r.Rejected = []Rejection{{event2, []string{"SCHEMA_INVALID"}}}
	r.Watermarks[0].Through = 1
	ack, e := b.validate(raw(t, r))
	if e != nil || ack.Through != 1 || len(ack.Rejected) != 1 {
		t.Fatalf("partial ack: %+v %v", ack, e)
	}
	r = goodResponse()
	r.Watermarks[0].Through = 500
	ack, e = b.validate(raw(t, r))
	if e != nil || ack.Through != 2 {
		t.Fatalf("server watermark must be capped by sent prefix: %+v %v", ack, e)
	}
	r = goodResponse()
	r.Accepted = []string{}
	r.Duplicates = []string{event1, event2}
	if _, e = b.validate(raw(t, r)); e != nil {
		t.Fatal(e)
	}
}

func TestStrictResponseJSON(t *testing.T) {
	b := mustBatch(t, input())
	valid := raw(t, goodResponse())
	for name, data := range map[string][]byte{
		"case coercion":   bytes.Replace(valid, []byte(`"batch_id"`), []byte(`"BATCH_ID"`), 1),
		"null array":      bytes.Replace(valid, []byte(`"duplicate_ids":[]`), []byte(`"duplicate_ids":null`), 1),
		"null number":     bytes.Replace(valid, []byte(`"acked_through":2`), []byte(`"acked_through":null`), 1),
		"null id":         bytes.Replace(valid, []byte(fmt.Sprintf(`"batch_id":%q`, batchID)), []byte(`"batch_id":null`), 1),
		"unknown field":   append([]byte(`{"unexpected":1,`), valid[1:]...),
		"duplicate field": append([]byte(fmt.Sprintf(`{"batch_id":%q,`, batchID)), valid[1:]...),
		"nested unknown":  bytes.Replace(valid, []byte(`"acked_through":2`), []byte(`"acked_through":2,"other":1`), 1),
		"missing field":   bytes.Replace(valid, []byte(`"duplicate_ids":[],`), nil, 1),
		"invalid UTF8":    bytes.Replace(valid, []byte("boot_instance"), []byte{255}, 1),
		"lone surrogate":  bytes.Replace(valid, []byte("boot_instance"), []byte(`\ud800`), 1),
		"exponent":        bytes.Replace(valid, []byte(`"acked_through":2`), []byte(`"acked_through":2e0`), 1),
		"trailing":        append(append([]byte{}, valid...), []byte(` {}`)...),
		"oversize":        []byte(strings.Repeat(" ", MaxBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := b.validate(data); e == nil {
				t.Fatal("accepted invalid response JSON")
			}
		})
	}
}

func TestRangeAndLifecycleCheckpoint(t *testing.T) {
	in := input()
	in.Records = in.Records[1:]
	digest, err := canonical.AbandonedRangeDigest("sensor", "kernel", "boot_instance", 1, 1, "wal_segment_corrupt")
	if err != nil {
		t.Fatal(err)
	}
	in.Abandoned = []Range{{1, 1, "wal_segment_corrupt", digest}}
	b := mustBatch(t, in)
	r := goodResponse()
	r.Accepted = []string{event2}
	if _, e := b.validate(raw(t, r)); e != nil {
		t.Fatal(e)
	}
	r.Rejected = []Rejection{{"boot_instance:1-1", []string{"EVENT_ID_CONFLICT"}}}
	if _, e := b.validate(raw(t, r)); e == nil {
		t.Fatal("crossed rejected gap")
	}
	in.Abandoned[0].Digest = strings.Repeat("a", 64)
	if _, e := New(in); e == nil {
		t.Fatal("accepted gap with a noncanonical digest")
	}
	in = input()
	in.Stream = Lifecycle
	in.SourceID = PodWatcherSource
	in.Scope = "namespace/agent-exec"
	in.Cursor = &Cursor{"namespace/agent-exec", "rv-9", 0}
	lifecycleIDs := []string{}
	for n, record := range in.Records {
		id, err := canonical.LifecycleEventID(PodWatcherSource, "boot_instance", int64(n+1))
		if err != nil {
			t.Fatal(err)
		}
		lifecycleIDs = append(lifecycleIDs, id)
		record = bytes.ReplaceAll(record, []byte([]string{event1, event2}[n]), []byte(id))
		in.Records[n] = bytes.ReplaceAll(bytes.ReplaceAll(bytes.ReplaceAll(record, []byte("source_event_id"), []byte("lifecycle_event_id")), []byte("sensor_id"), []byte("source_id")), []byte(`"sensor"`), []byte(fmt.Sprintf(`%q,"namespace":"agent-exec"`, PodWatcherSource)))
	}
	b = mustBatch(t, in)
	r = goodResponse()
	r.Accepted = lifecycleIDs
	r.Checkpoint = &Checkpoint{"namespace/agent-exec", "rv-9", 1}
	if _, e := b.validate(raw(t, r)); e != nil {
		t.Fatal(e)
	}
	r.Watermarks[0].Through = 1
	if _, e := b.validate(raw(t, r)); e == nil {
		t.Fatal("advanced cursor before whole batch ack")
	}
	r.Watermarks[0].Through = 2
	r.Checkpoint.ResourceVersion = "rv-10"
	if _, e := b.validate(raw(t, r)); e == nil {
		t.Fatal("accepted changed cursor")
	}
}

func TestGapWatermarkCannotSplitRange(t *testing.T) {
	in := input()
	in.Records = nil
	digest, err := canonical.AbandonedRangeDigest("sensor", "kernel", "boot_instance", 1, 10, "wal_segment_corrupt")
	if err != nil {
		t.Fatal(err)
	}
	in.Abandoned = []Range{{1, 10, "wal_segment_corrupt", digest}}
	b := mustBatch(t, in)
	r := goodResponse()
	r.Accepted = []string{}
	r.Watermarks[0].Through = 5
	if _, err := b.validate(raw(t, r)); err == nil {
		t.Fatal("accepted watermark inside atomic range")
	}
	r.Watermarks[0].Through = 10
	if ack, err := b.validate(raw(t, r)); err != nil || ack.Through != 10 {
		t.Fatalf("whole gap acknowledgement: %+v %v", ack, err)
	}
}

func tlsFixture(t *testing.T, h http.Handler) (*httptest.Server, *tls.Config) {
	return tlsFixtureServer(t, h, nil)
}
func tlsFixtureServer(t *testing.T, h http.Handler, alter func(*x509.Certificate)) (*httptest.Server, *tls.Config) {
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
		if usage == x509.ExtKeyUsageServerAuth && alter != nil {
			alter(cert)
		}
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

func TestLostResponseReplaysWALBeforeDeletion(t *testing.T) {
	dir := t.TempDir() + "/spool"
	j, e := wal.Open(dir, "boot_instance", 0)
	if e != nil {
		t.Fatal(e)
	}
	_, e = j.Append(func(_ string, seq uint64) ([]byte, error) { return record(event1, seq), nil }, wal.Checkpoint{Inode: 1, Offset: 42})
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	j, e = wal.Open(dir, "next_instance", 0)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	pending, e := j.Pending()
	if e != nil || len(pending) != 1 {
		t.Fatalf("replay %v %v", pending, e)
	}
	in := input()
	in.Records = []json.RawMessage{pending[0].Payload}
	b := mustBatch(t, in)
	var calls atomic.Int32
	s, config := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			t.Error("missing client certificate")
		}
		body, e := io.ReadAll(r.Body)
		if e != nil || !bytes.Equal(body, b.Bytes()) {
			t.Errorf("retry bytes differ: %v", e)
		}
		if r.URL.Path != "/internal/kernel/events:batch" || r.Method != "POST" {
			t.Error("wrong route")
		}
		if calls.Add(1) == 1 {
			conn, _, e := w.(http.Hijacker).Hijack()
			if e != nil {
				t.Error(e)
				return
			}
			_ = conn.Close()
			return
		}
		result := goodResponse()
		result.Accepted = []string{}
		result.Duplicates = []string{event1}
		result.Watermarks[0].Through = 1
		_ = json.NewEncoder(w).Encode(result)
	}))
	c, e := NewClient(s.URL, config)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = c.Send(context.Background(), b); e == nil {
		t.Fatal("lost response acknowledged")
	}
	if p, e := j.Pending(); e != nil || len(p) != 1 {
		t.Fatal("WAL lost before verified ack")
	}
	ack, e := c.Send(context.Background(), b)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Ack(ack.Epoch, ack.Through); e != nil {
		t.Fatal(e)
	}
	if p, e := j.Pending(); e != nil || len(p) != 0 {
		t.Fatal("committed duplicate did not release WAL")
	}
	if calls.Load() != 2 {
		t.Fatal("unexpected retry count")
	}
}

func TestHTTPSFailuresAndRedirects(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls.Add(1) }))
	defer destination.Close()
	var mode atomic.Int32
	s, config := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 0:
			http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
		case 1:
			w.WriteHeader(503)
			_, _ = w.Write([]byte("provider secret should not appear"))
		case 2:
			_, _ = w.Write([]byte(strings.Repeat(" ", MaxBytes+1)))
		case 3:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	c, e := NewClient(s.URL, config)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	b := mustBatch(t, input())
	for i := int32(0); i < 4; i++ {
		mode.Store(i)
		_, e = c.Send(context.Background(), b)
		if e == nil {
			t.Fatalf("accepted mode %d", i)
		}
		if strings.Contains(e.Error(), "provider secret") {
			t.Fatal("echoed response body")
		}
		if i == 1 {
			var he *HTTPError
			if !errors.As(e, &he) || !he.Retryable() {
				t.Fatal("503 not retryable")
			}
		}
	}
	if destinationCalls.Load() != 0 {
		t.Fatal("followed redirect")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.Send(ctx, b); !errors.Is(e, context.Canceled) {
		t.Fatalf("canceled request: %v", e)
	}
	for _, origin := range []string{"http://localhost", "https://user:password@localhost", "https://localhost/internal", "https://localhost?x=1", "https://localhost#x"} {
		if _, e := NewClient(origin, config); e == nil {
			t.Fatalf("accepted origin %s", origin)
		}
	}
	bad := config.Clone()
	bad.InsecureSkipVerify = true
	if _, e := NewClient(s.URL, bad); e == nil {
		t.Fatal("accepted insecure TLS")
	}
	bad = config.Clone()
	bad.RootCAs = x509.NewCertPool()
	untrusted, e := NewClient(s.URL, bad)
	if e != nil {
		t.Fatal(e)
	}
	defer untrusted.Close()
	if _, e = untrusted.Send(context.Background(), b); e == nil {
		t.Fatal("accepted untrusted server")
	}
}

func TestCollectorRequiresExactURIServerCertificate(t *testing.T) {
	for _, tt := range []struct {
		name  string
		alter func(*x509.Certificate)
	}{
		{"wrong URI", func(c *x509.Certificate) { c.URIs[0].Path = "/ns/agent-observe/sa/control-health" }},
		{"extra URI", func(c *x509.Certificate) { c.URIs = append(c.URIs, c.URIs[0]) }},
		{"no URI", func(c *x509.Certificate) { c.URIs = nil }},
		{"client only EKU", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			server, cfg := tlsFixtureServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }), tt.alter)
			c, err := NewClient(server.URL, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err = c.Send(context.Background(), mustBatch(t, input())); err == nil {
				t.Fatal("accepted invalid collector identity")
			}
			if calls.Load() != 0 {
				t.Fatal("sent body before authenticated handshake")
			}
		})
	}
}
