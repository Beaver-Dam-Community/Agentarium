package netpolcollector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/netpol-collector/internal/receivertest"
)

const (
	q0Log      = "../../evidence/gcp/runs/20261014-task01-q0-min/raw/netpol-policy_action.log"
	q0NodeName = "gke-agentarium-prod-exec-pool-eaf0304a-x10z"
)

// epochFor follows the runtime source encoding: node 32hex + boot 64hex + instance 32hex.
func epochFor(instance byte) string {
	return strings.ReplaceAll(nodeUID, "-", "") + strings.Repeat("b", 64) + strings.Repeat(string(instance), 32)
}

func newSenderRig(t *testing.T) (*receivertest.Receiver, string, func(string) *Sender, func() *wal.Journal) {
	p := receivertest.NewPKI()
	recv := receivertest.New(clusterUID)
	srv := p.Server(ReceiverSAN, recv, true)
	t.Cleanup(srv.Close)
	clientCert := p.Pair(CollectorSAN, x509.ExtKeyUsageClientAuth)
	client := HTTPSClient(ReceiverSAN, func() (*x509.CertPool, error) { return p.Pool, nil }, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &clientCert, nil })
	dir := filepath.Join(t.TempDir(), "spool")
	var journal *wal.Journal
	open := func(epoch string) *Sender {
		if journal != nil {
			journal.Close()
		}
		j, err := wal.Open(dir, epoch, 0)
		if err != nil {
			t.Fatal(err)
		}
		journal = j
		t.Cleanup(func() { j.Close() })
		return &Sender{Journal: j, Epoch: epoch, Client: client, Origin: srv.URL}
	}
	return recv, dir, open, func() *wal.Journal { return journal }
}

func captureQ0(t *testing.T, j *wal.Journal) {
	c, err := New(Config{Journal: j, Reader: Reader{Inventory: func() ([]string, error) { abs, _ := filepath.Abs(q0Log); return []string{abs}, nil }, MaxFiles: 1, MaxLineBytes: wal.MaxRecordBytes}, ClusterUID: clusterUID, NodeUID: nodeUID, NodeName: q0NodeName, NormalizationVersion: "test-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Run(context.Background(), false); err != nil {
		t.Fatal(err)
	}
}

func TestSenderDeliversQ0RecordsWithAckLossReplayAndFinalFlush(t *testing.T) {
	recv, _, open, journal := newSenderRig(t)
	ctx := context.Background()
	first := open(epochFor('1'))
	captureQ0(t, journal())

	// Receiver down: nothing is acknowledged and the WAL keeps all five.
	if _, err := first.Send(ctx, Signals{}); err == nil {
		t.Fatal("503 must be an error")
	} else {
		var h *HTTPError
		if !errors.As(err, &h) || !h.Retryable() {
			t.Fatalf("503 must be retryable: %v", err)
		}
	}
	// Commit happens but the ACK is lost; the identical batch is resent.
	recv.Lock()
	recv.Available, recv.DropNext = true, true
	recv.Unlock()
	if _, err := first.Send(ctx, Signals{}); err == nil {
		t.Fatal("lost ACK must be an error")
	}
	// Crash before any ACK: a new process epoch replays the old epoch first.
	second := open(epochFor('2'))
	now := time.Now()
	res, err := second.Send(ctx, Signals{CaughtUpAt: &now})
	if err != nil || res.Epoch != epochFor('1') || res.Acked != 5 || !res.Complete {
		t.Fatalf("old epoch replay: %+v %v", res, err)
	}
	pending, _ := journal().Pending()
	if len(pending) != 0 {
		t.Fatalf("WAL not drained: %d", len(pending))
	}
	// SIGTERM path: everything acknowledged, final flush recorded.
	res, err = second.Send(ctx, Signals{CaughtUpAt: &now, FinalFlush: true})
	if err != nil || !res.FinalRecorded {
		t.Fatalf("final flush: %+v %v", res, err)
	}
	recv.Lock()
	defer recv.Unlock()
	if len(recv.Violations) != 0 {
		t.Fatalf("contract: %v", recv.Violations)
	}
	if len(recv.Records) != 5 || recv.Acked[epochFor('1')] != 5 {
		t.Fatalf("records %d acked %v", len(recv.Records), recv.Acked)
	}
	allow, deny, packets := 0, 0, int64(0)
	for _, r := range recv.Records {
		n, _ := r["count"].(interface{ Int64() (int64, error) }).Int64()
		packets += n
		if r["disposition"] == "allow" {
			allow++
			if r["policies"] == nil {
				t.Fatalf("allow record lost policies: %v", r)
			}
		} else {
			deny++
			if r["policies"] != nil {
				t.Fatalf("deny record must have no policies: %v", r)
			}
		}
		if r["node_name"] != q0NodeName || r["normalization_version"] != "test-v1" {
			t.Fatalf("record fields: %v", r)
		}
	}
	if allow != 3 || deny != 2 || packets != 12 {
		t.Fatalf("Q0 dispositions allow=%d deny=%d packets=%d", allow, deny, packets)
	}
	if recv.Final[epochFor('2')] != 0 || len(recv.CaughtUp) == 0 {
		t.Fatalf("final flush must be recorded for the current epoch at its watermark: %v caught=%v", recv.Final, recv.CaughtUp)
	}
	if _, ok := recv.Final[epochFor('2')]; !ok {
		t.Fatal("final flush not recorded")
	}
}

func TestRotationLossIsReportedAfterBacklog(t *testing.T) {
	recv, _, open, journal := newSenderRig(t)
	recv.Lock()
	recv.Available = true
	recv.Unlock()
	s := open(epochFor('3'))
	captureQ0(t, journal())
	lost := time.Now()
	// The first call must carry the five records and the loss marker together
	// (the batch covers everything pending).
	res, err := s.Send(context.Background(), Signals{RotationLoss: &lost})
	if err != nil || res.Acked != 5 {
		t.Fatalf("%+v %v", res, err)
	}
	recv.Lock()
	defer recv.Unlock()
	if len(recv.Rotation) != 1 || recv.Rotation[0]["after_sequence"].(float64) != 5 || len(recv.Violations) != 0 {
		t.Fatalf("rotation loss %v violations %v", recv.Rotation, recv.Violations)
	}
}

func TestWireRecordRejectsMismatchedPosition(t *testing.T) {
	_, _, open, journal := newSenderRig(t)
	open(epochFor('4'))
	captureQ0(t, journal())
	pending, err := journal().Pending()
	if err != nil || len(pending) != 5 {
		t.Fatal(err)
	}
	if _, err := WireRecord(pending[0].Payload, epochFor('4'), pending[0].Sequence+1); err == nil {
		t.Fatal("sequence mismatch accepted")
	}
	if _, err := WireRecord(pending[0].Payload, epochFor('5'), pending[0].Sequence); err == nil {
		t.Fatal("epoch mismatch accepted")
	}
	a, err := WireRecord(pending[0].Payload, epochFor('4'), pending[0].Sequence)
	b, _ := WireRecord(pending[0].Payload, epochFor('4'), pending[0].Sequence)
	if err != nil || a.RecordID != b.RecordID || a.SourceTime == "" {
		t.Fatalf("wire record must be deterministic: %v", err)
	}
}

// Review #175: an idle send keeps the real watermark, the final flush names the
// last allocated sequence, and SCHEMA_INVALID is quarantined and replaced by a
// record_rejected range instead of stalling delivery.
func TestIdleWatermarkFinalThroughAndSchemaRejection(t *testing.T) {
	recv, _, open, journal := newSenderRig(t)
	recv.Lock()
	recv.Available, recv.RejectSequence = true, 2
	recv.Unlock()
	ctx := context.Background()
	s := open(epochFor('6'))
	captureQ0(t, journal())
	res, err := s.Send(ctx, Signals{})
	if err != nil || res.Quarantined != 1 || res.Acked != 1 {
		t.Fatalf("rejection: %+v %v", res, err)
	}
	res, err = s.Send(ctx, Signals{})
	if err != nil || res.Acked != 5 || !res.Complete {
		t.Fatalf("after record_rejected range: %+v %v", res, err)
	}
	res, err = s.Send(ctx, Signals{})
	if err != nil || !res.Idle || res.Acked != 5 {
		t.Fatalf("idle send must keep acked_through=5: %+v %v", res, err)
	}
	now := time.Now()
	res, err = s.Send(ctx, Signals{CaughtUpAt: &now, FinalFlush: true})
	if err != nil || !res.FinalRecorded || !res.CaughtUpSent {
		t.Fatalf("final flush: %+v %v", res, err)
	}
	recv.Lock()
	defer recv.Unlock()
	if len(recv.Violations) != 0 || recv.Rejections != 1 || recv.RejectedRanges != 1 || recv.Final[epochFor('6')] != 5 || len(recv.Records) != 4 {
		t.Fatalf("violations=%v rejections=%d ranges=%d final=%v records=%d", recv.Violations, recv.Rejections, recv.RejectedRanges, recv.Final, len(recv.Records))
	}
}

// A rejection reason other than SCHEMA_INVALID stops delivery permanently
// and keeps every WAL record.
func TestOtherRejectionIsPermanent(t *testing.T) {
	recv, _, open, journal := newSenderRig(t)
	recv.Lock()
	recv.Available, recv.RejectSequence, recv.RejectReason = true, 1, "EVENT_ID_CONFLICT"
	recv.Unlock()
	s := open(epochFor('7'))
	captureQ0(t, journal())
	_, err := s.Send(context.Background(), Signals{})
	var rejected *RejectedError
	if !errors.As(err, &rejected) || rejected.Reasons[0] != "EVENT_ID_CONFLICT" {
		t.Fatalf("want permanent rejection, got %v", err)
	}
	if pending, _ := journal().Pending(); len(pending) != 5 {
		t.Fatalf("WAL must be retained: %d", len(pending))
	}
}
