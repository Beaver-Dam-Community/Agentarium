package receiver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/netpol"
	"github.com/google/uuid"
)

type fakeIdentity struct {
	cert Certificate
	ok   bool
	err  error
	got  []string
}

func (f *fakeIdentity) Lookup(_ context.Context, serial, san, hash string) (Certificate, bool, error) {
	f.got = []string{serial, san, hash}
	return f.cert, f.ok, f.err
}

type fakeStore struct {
	node  netpol.NodeIdentity
	batch netpol.Batch
	calls int
	ack   netpol.Ack
}

func (f *fakeStore) Ingest(_ context.Context, n netpol.NodeIdentity, b netpol.Batch) (netpol.Ack, error) {
	f.calls++
	f.node, f.batch = n, b
	ack := f.ack
	for _, r := range b.Records {
		ack.AcceptedIDs = append(ack.AcceptedIDs, r.RecordID)
	}
	return ack, nil
}

var (
	cluster = uuid.MustParse("6f1c3a4e-8f0e-4d4c-9b55-0d9e0c1b2a3f")
	node    = uuid.MustParse("1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed")
	boot    = "boot-a"
)

func epochFor(n uuid.UUID, b string) string {
	sum := sha256.Sum256([]byte(b))
	return strings.ReplaceAll(n.String(), "-", "") + hex.EncodeToString(sum[:]) + strings.Repeat("ab", 16)
}

func record(t *testing.T, epoch string, seq int64, mut func(map[string]any)) map[string]any {
	id, err := canonical.NetworkPolicyRecordID(cluster.String(), node.String(), epoch, seq)
	if err != nil {
		t.Fatal(err)
	}
	r := map[string]any{"record_id": id, "cluster_uid": cluster.String(), "node_uid": node.String(), "source_epoch": epoch, "source_sequence": seq,
		"node_name": "gke-node-1", "source_time": "2026-10-17T10:00:00Z", "disposition": "deny", "direction": "egress", "protocol": "tcp",
		"src_ip": "10.20.0.5", "dest_ip": "203.0.113.10", "dest_port": 443, "src_endpoint": map[string]any{"namespace": "agent-exec", "pod_name": "runtime-a"},
		"count": 1, "normalization_version": "v1"}
	if mut != nil {
		mut(r)
	}
	return r
}

func body(t *testing.T, b map[string]any) []byte {
	raw, _ := json.Marshal(b)
	digest, err := canonical.BatchDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	b["batch_digest"] = digest
	raw, _ = json.Marshal(b)
	return raw
}

func leaf(san string) *x509.Certificate {
	u, _ := url.Parse(san)
	return &x509.Certificate{URIs: []*url.URL{u}, SerialNumber: big.NewInt(0x1a2b)}
}

func post(h Handler, raw []byte, cert *x509.Certificate) (*httptest.ResponseRecorder, response) {
	req := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(raw))
	if cert != nil {
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var resp response
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp
}

func setup() (Handler, *fakeIdentity, *fakeStore) {
	n := node
	id := &fakeIdentity{cert: Certificate{Namespace: "agent-sensors", KSA: "netpol-collector", NodeUID: &n, BootID: &boot}, ok: true}
	st := &fakeStore{ack: netpol.Ack{AckedThrough: 2}}
	return Handler{ClusterUID: cluster, Identity: id, Store: st}, id, st
}

func TestBatchAcceptsBoundCollector(t *testing.T) {
	h, id, st := setup()
	epoch := epochFor(node, boot)
	rangeDigest, _ := canonical.AbandonedRangeDigest(netpol.CollectorSAN, "network_policy", epoch, 3, 3, "record_rejected")
	raw := body(t, map[string]any{"batch_id": uuid.NewString(), "source_epoch": epoch,
		"records": []any{record(t, epoch, 1, nil), record(t, epoch, 2, func(r map[string]any) {
			r["disposition"] = "allow"
			r["policies"] = []any{map[string]any{"name": "p", "namespace": "agent-exec"}}
		})},
		"sequence_range_abandoned": []any{map[string]any{"from_seq": 3, "to_seq": 3, "reason": "record_rejected", "range_digest": rangeDigest}},
		"caught_up_at":             "2026-10-17T10:00:05Z", "final_flush": map[string]any{"through_sequence": 3, "caught_up_at": "2026-10-17T10:00:05Z"}})
	w, resp := post(h, raw, leaf(netpol.CollectorSAN))
	if w.Code != 200 || len(resp.AcceptedIDs) != 2 || len(resp.Rejected) != 0 || resp.Watermarks[0].AckedThrough != 2 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if id.got[0] != "1a2b" || id.got[1] != netpol.CollectorSAN || id.got[2] != epoch[32:96] {
		t.Fatalf("lookup %v", id.got)
	}
	if st.node.NodeUID != node || st.node.ClusterUID != cluster || *st.node.BootID != boot || len(st.batch.Abandoned) != 1 || st.batch.FinalFlush.ThroughSequence != 3 || st.batch.CaughtUpAt == nil {
		t.Fatalf("store input %+v %+v", st.node, st.batch)
	}
	// A retained prior-issued boot of the same node may replay its epoch.
	old := "boot-old"
	id.cert.HistoricalBoot = &old
	oldEpoch := epochFor(node, old)
	if w, _ := post(h, body(t, map[string]any{"batch_id": uuid.NewString(), "source_epoch": oldEpoch, "records": []any{record(t, oldEpoch, 1, nil)}, "sequence_range_abandoned": []any{}}), leaf(netpol.CollectorSAN)); w.Code != 200 {
		t.Fatalf("historical boot replay %d %s", w.Code, w.Body)
	}
	if st.node.BootID == nil || *st.node.BootID != old {
		t.Fatalf("historical epoch stored with boot %+v", st.node.BootID)
	}
}

func TestBatchRejectsUnboundIdentity(t *testing.T) {
	epoch := epochFor(node, boot)
	raw := body(t, map[string]any{"batch_id": uuid.NewString(), "source_epoch": epoch, "records": []any{record(t, epoch, 1, nil)}, "sequence_range_abandoned": []any{}})
	other := uuid.New()
	cases := map[string]func(*Handler, *fakeIdentity) *x509.Certificate{
		"no client certificate": func(*Handler, *fakeIdentity) *x509.Certificate { return nil },
		"other SAN": func(*Handler, *fakeIdentity) *x509.Certificate {
			return leaf("spiffe://agentarium.internal/ns/agent-sensors/sa/kernel-exporter")
		},
		"two SANs": func(*Handler, *fakeIdentity) *x509.Certificate {
			c := leaf(netpol.CollectorSAN)
			c.URIs = append(c.URIs, c.URIs[0])
			return c
		},
		"certificate not current": func(_ *Handler, id *fakeIdentity) *x509.Certificate { id.ok = false; return leaf(netpol.CollectorSAN) },
		"certificate without node": func(_ *Handler, id *fakeIdentity) *x509.Certificate {
			id.cert.NodeUID = nil
			return leaf(netpol.CollectorSAN)
		},
		"epoch of another node": func(_ *Handler, id *fakeIdentity) *x509.Certificate {
			id.cert.NodeUID = &other
			return leaf(netpol.CollectorSAN)
		},
		"epoch of another boot": func(_ *Handler, id *fakeIdentity) *x509.Certificate {
			b := "boot-b"
			id.cert.BootID = &b
			return leaf(netpol.CollectorSAN)
		},
	}
	for name, prepare := range cases {
		h, id, st := setup()
		cert := prepare(&h, id)
		if w, _ := post(h, raw, cert); w.Code != http.StatusForbidden || st.calls != 0 {
			t.Errorf("%s: %d calls=%d", name, w.Code, st.calls)
		}
	}
	h, id, st := setup()
	id.err = errors.New("db down")
	if w, _ := post(h, raw, leaf(netpol.CollectorSAN)); w.Code != http.StatusServiceUnavailable || st.calls != 0 {
		t.Fatalf("lookup failure %d", w.Code)
	}
}

func TestBatchSchema(t *testing.T) {
	epoch := epochFor(node, boot)
	good := func() map[string]any {
		return map[string]any{"batch_id": uuid.NewString(), "source_epoch": epoch, "records": []any{}, "sequence_range_abandoned": []any{}}
	}
	whole := map[string][]byte{}
	b := good()
	b["unknown"] = 1
	whole["unknown field"] = body(t, b)
	b = good()
	b["rotation_loss"] = map[string]any{"detected_at": "2026-10-17T10:00:05Z", "after_sequence": 4}
	b["caught_up_at"] = "2026-10-17T10:00:05Z"
	whole["rotation_loss with caught_up_at"] = body(t, b)
	b = good()
	b["source_epoch"] = "short"
	whole["epoch format"] = body(t, b)
	var signed map[string]any
	_ = json.Unmarshal(body(t, good()), &signed)
	signed["batch_id"] = uuid.NewString() // changed after the digest was computed
	whole["digest mismatch"], _ = json.Marshal(signed)
	b = good()
	delete(b, "sequence_range_abandoned")
	whole["missing ranges"] = body(t, b)
	for name, raw := range whole {
		h, _, st := setup()
		if w, _ := post(h, raw, leaf(netpol.CollectorSAN)); w.Code != http.StatusUnprocessableEntity || st.calls != 0 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	// Individual records and ranges are rejected; valid siblings are stored.
	bad := map[string]func(map[string]any){
		"record_id":     func(r map[string]any) { r["record_id"] = uuid.NewString() },
		"cluster":       func(r map[string]any) { r["cluster_uid"] = uuid.NewString() },
		"node":          func(r map[string]any) { r["node_uid"] = uuid.NewString() },
		"received_at":   func(r map[string]any) { r["received_at"] = "2026-10-17T10:00:00Z" },
		"deny policies": func(r map[string]any) { r["policies"] = []any{map[string]any{"name": "p", "namespace": "n"}} },
		"count":         func(r map[string]any) { delete(r, "count") },
	}
	for name, mut := range bad {
		h, _, st := setup()
		b := good()
		b["records"] = []any{record(t, epoch, 1, nil), record(t, epoch, 2, mut)}
		w, resp := post(h, body(t, b), leaf(netpol.CollectorSAN))
		if w.Code != 200 || len(st.batch.Records) != 1 || len(resp.Rejected) != 1 || resp.Rejected[0].ReasonCodes[0] != "SCHEMA_INVALID" {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	h, _, st := setup()
	b = good()
	b["sequence_range_abandoned"] = []any{map[string]any{"from_seq": 1, "to_seq": 1, "reason": "record_rejected", "range_digest": strings.Repeat("0", 64)}}
	w, resp := post(h, body(t, b), leaf(netpol.CollectorSAN))
	if w.Code != 200 || len(st.batch.Abandoned) != 0 || len(resp.Rejected) != 1 || resp.Rejected[0].ID != epoch+":1-1" {
		t.Fatalf("range digest %d %s", w.Code, w.Body)
	}
}
