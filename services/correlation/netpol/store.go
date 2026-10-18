package netpol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/netpol/netpoldb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Config is the trusted correlation audit source (installation input).
type Config struct{ SourceID, Version, Epoch string }

// Store persists NetworkPolicyRecords, watermarks and NetworkFinding revisions.
// It is an internal adapter: the HTTP receiver (internal/receiver)
// authenticates the node collector and supplies NodeIdentity.
type Store struct {
	Pool       *pgxpool.Pool
	Config     Config
	Classifier *Classifier
}

// NodeIdentity must come from the verified collector certificate (node UID
// and boot bound at issuance), never from the request body.
type NodeIdentity struct {
	ClusterUID, NodeUID uuid.UUID
	BootID              *string
}

type EndpointRef struct {
	Namespace    *string `json:"namespace,omitempty"`
	PodName      *string `json:"pod_name,omitempty"`
	WorkloadName *string `json:"workload_name,omitempty"`
	WorkloadKind *string `json:"workload_kind,omitempty"`
	Instance     *string `json:"instance,omitempty"`
}
type PolicyRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// BatchRecord carries the COMMON NetworkPolicyRecord fields the collector
// copies from the node log file; values are not rewritten. RecordID is the
// canonical.NetworkPolicyRecordID the receiver verified.
type BatchRecord struct {
	RecordID             uuid.UUID
	SourceSequence       int64
	NodeName             string
	SourceTime           time.Time
	Disposition          string
	Direction            string
	Protocol             string
	SrcIP, DestIP        netip.Addr
	SrcPort, DestPort    *int
	SrcEndpoint          *EndpointRef
	DestEndpoint         *EndpointRef
	Policies             []PolicyRef
	Count                *int
	NormalizationVersion string
}
type FinalFlush struct {
	ThroughSequence int64
	CaughtUpAt      time.Time
}

// AbandonedRange is a sequence_range_abandoned entry whose range_digest the
// receiver verified against the authenticated collector SAN.
type AbandonedRange struct {
	From, To int64
	Reason   string
	Digest   string
}
type RotationLoss struct {
	DetectedAt    time.Time
	AfterSequence int64
}
type Batch struct {
	SourceEpoch  string
	Records      []BatchRecord
	Abandoned    []AbandonedRange
	CaughtUpAt   *time.Time
	FinalFlush   *FinalFlush
	RotationLoss *RotationLoss
}

// Rejection is one individually refused record or range (COMMON reason codes).
type Rejection struct {
	ID          string
	ReasonCodes []string
}
type Ack struct {
	AcceptedIDs, DuplicateIDs []uuid.UUID
	Rejected                  []Rejection
	SourceEpoch               string
	AckedThrough              int64
	FinalFlushRecorded        bool
	BackfilledGapIDs          []uuid.UUID
	LossGapIDs                []uuid.UUID
}

func pgUUID(u uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: u, Valid: true} }
func pgTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}
func pgInt(p *int) pgtype.Int4 {
	if p == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: int32(*p), Valid: true}
}

// ValidRecord applies the NetworkPolicyRecord field rules.
func ValidRecord(r BatchRecord) bool {
	if r.RecordID == uuid.Nil || r.SourceSequence < 1 || r.NodeName == "" || r.SourceTime.IsZero() || !slices.Contains([]string{"allow", "deny"}, r.Disposition) ||
		!slices.Contains([]string{"ingress", "egress"}, r.Direction) || !slices.Contains([]string{"tcp", "udp", "icmp"}, r.Protocol) ||
		!r.SrcIP.IsValid() || !r.DestIP.IsValid() || r.NormalizationVersion == "" || (r.Count != nil && *r.Count < 1) {
		return false
	}
	if r.Protocol == "icmp" && (r.SrcPort != nil || r.DestPort != nil) {
		return false
	}
	for _, p := range []*int{r.SrcPort, r.DestPort} {
		if p != nil && (*p < 0 || *p > 65535) {
			return false
		}
	}
	return r.Disposition == "allow" || r.Policies == nil
}

func (s Store) audit(ctx context.Context, q *netpoldb.Queries, kind string, payload map[string]any, refs []string, now time.Time) error {
	return s.auditAs(ctx, q, "", kind, payload, refs, now)
}

// auditAs records the verified collector as authenticated_actor for events
// caused by its declaration (COMMON receiver atomic audit).
func (s Store) auditAs(ctx context.Context, q *netpoldb.Queries, actor, kind string, payload map[string]any, refs []string, now time.Time) error {
	if s.Config.SourceID == "" || s.Config.Version == "" || s.Config.Epoch == "" {
		return errors.New("audit source/version/epoch required")
	}
	event := map[string]any{"event_id": uuid.NewString(), "event_type": kind, "tenant": "*", "source_id": s.Config.SourceID,
		"source_version": s.Config.Version, "source_epoch": s.Config.Epoch, "source_sequence": nil,
		"source_time": now.UTC().Format(time.RFC3339Nano), "schema_version": 1, "safe_payload": payload, "evidence_refs": refs}
	if actor != "" {
		event["authenticated_actor"] = actor
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	digest, err := canonical.PayloadDigest(raw)
	if err != nil {
		return err
	}
	event["payload_digest"] = digest
	if raw, err = json.Marshal(event); err != nil {
		return err
	}
	result, err := q.AppendAudit(ctx, raw)
	if err != nil {
		return err
	}
	if result != "created" {
		return errors.New("network policy audit append did not create event")
	}
	return nil
}

// CollectorActor is the verified requester of every collector batch.
const CollectorActor = "service:agent-sensors/netpol-collector"

// CollectorSAN is the shared mTLS identity of every node collector; range
// digests are bound to it.
const CollectorSAN = "spiffe://agentarium.internal/ns/agent-sensors/sa/netpol-collector"

func conflict(id string) Rejection {
	return Rejection{ID: id, ReasonCodes: []string{"EVENT_ID_CONFLICT"}}
}

// RangeID is the rejection id of an abandoned range (`epoch:from-to`).
func RangeID(epoch string, from, to int64) string { return fmt.Sprintf("%s:%d-%d", epoch, from, to) }

// Ingest stores one collector batch: duplicates by (node, epoch, sequence) are
// acknowledged without a second row and a resend with different content is an
// individual EVENT_ID_CONFLICT; a new abandoned range becomes an unrecoverable
// SEQUENCE_RANGE_ABANDONED gap; the watermark moves only over contiguous
// stored sequences and ranges; a final flush is recorded only once acked
// through its sequence; rotation_loss records NETPOL_FILE_ROTATION_LOSS and
// closes the open collector-stopped gap; caught_up_at backfills that gap.
// Everything commits in one transaction with its audit events.
func (s Store) Ingest(ctx context.Context, node NodeIdentity, b Batch) (Ack, error) {
	ack := Ack{SourceEpoch: b.SourceEpoch, AcceptedIDs: []uuid.UUID{}, DuplicateIDs: []uuid.UUID{}, Rejected: []Rejection{}, BackfilledGapIDs: []uuid.UUID{}, LossGapIDs: []uuid.UUID{}}
	if node.NodeUID == uuid.Nil || node.ClusterUID == uuid.Nil || b.SourceEpoch == "" {
		return ack, errors.New("verified node identity and source epoch required")
	}
	if b.RotationLoss != nil && b.CaughtUpAt != nil {
		return ack, errors.New("rotation_loss batch cannot claim caught_up_at")
	}
	for _, r := range b.Records {
		if !ValidRecord(r) {
			return ack, fmt.Errorf("invalid record sequence %d", r.SourceSequence)
		}
	}
	sourceID := "netpol-node/" + node.NodeUID.String()
	var boot pgtype.Text
	if node.BootID != nil {
		boot = pgtype.Text{String: *node.BootID, Valid: true}
	}
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		q := netpoldb.New(tx)
		if err := q.LimitLockWait(ctx); err != nil {
			return err
		}
		// One lock per node serialises every epoch's watermark and the node's
		// collector gaps.
		if err := q.LockKey(ctx, "correlation/netpol/"+node.NodeUID.String()); err != nil {
			return err
		}
		clock, err := q.Clock(ctx)
		if err != nil {
			return err
		}
		key := netpoldb.WatermarkParams{NodeUid: pgUUID(node.NodeUID), SourceEpoch: b.SourceEpoch}
		current, err := q.Watermark(ctx, key)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		for _, r := range b.Records {
			covered, err := q.AbandonedCovers(ctx, netpoldb.AbandonedCoversParams{NodeUid: key.NodeUid, SourceEpoch: key.SourceEpoch, Sequence: r.SourceSequence})
			if err != nil {
				return err
			}
			if covered {
				ack.Rejected = append(ack.Rejected, conflict(r.RecordID.String()))
				continue
			}
			count := 1
			if r.Count != nil {
				count = *r.Count
			}
			var src, dest, policies []byte
			if r.SrcEndpoint != nil {
				src, _ = json.Marshal(r.SrcEndpoint)
			}
			if r.DestEndpoint != nil {
				dest, _ = json.Marshal(r.DestEndpoint)
			}
			if r.Policies != nil {
				policies, _ = json.Marshal(r.Policies)
			}
			id, err := q.InsertRecord(ctx, netpoldb.InsertRecordParams{RecordID: pgUUID(r.RecordID), ClusterUid: pgUUID(node.ClusterUID), NodeUid: key.NodeUid, SourceEpoch: b.SourceEpoch,
				SourceSequence: r.SourceSequence, NodeName: r.NodeName, SourceTime: pgTime(r.SourceTime), Disposition: r.Disposition, Direction: r.Direction,
				Protocol: r.Protocol, SrcIp: r.SrcIP, SrcPort: pgInt(r.SrcPort), DestIp: r.DestIP, DestPort: pgInt(r.DestPort),
				SrcEndpoint: src, DestEndpoint: dest, Policies: policies, Count: int32(count), NormalizationVersion: r.NormalizationVersion})
			if errors.Is(err, pgx.ErrNoRows) {
				prior, err := q.RecordAt(ctx, netpoldb.RecordAtParams{NodeUid: key.NodeUid, SourceEpoch: b.SourceEpoch, SourceSequence: r.SourceSequence,
					SourceTime: pgTime(r.SourceTime), Disposition: r.Disposition, Direction: r.Direction, Protocol: r.Protocol, SrcIp: r.SrcIP, SrcPort: pgInt(r.SrcPort),
					DestIp: r.DestIP, DestPort: pgInt(r.DestPort), SrcEndpoint: src, DestEndpoint: dest, Policies: policies, Count: int32(count),
					NormalizationVersion: r.NormalizationVersion, ClusterUid: pgUUID(node.ClusterUID), NodeName: r.NodeName})
				if err != nil {
					return err
				}
				// A resend must carry the same record; different content for a
				// stored sequence is a conflict, never a silent duplicate ack.
				if !prior.Same || uuid.UUID(prior.RecordID.Bytes) != r.RecordID {
					ack.Rejected = append(ack.Rejected, conflict(r.RecordID.String()))
					continue
				}
				ack.DuplicateIDs = append(ack.DuplicateIDs, r.RecordID)
				continue
			}
			if err != nil {
				return err
			}
			ack.AcceptedIDs = append(ack.AcceptedIDs, uuid.UUID(id.Bytes))
		}
		for _, a := range b.Abandoned {
			rangeID := RangeID(b.SourceEpoch, a.From, a.To)
			prior, err := q.AbandonedAt(ctx, netpoldb.AbandonedAtParams{NodeUid: key.NodeUid, SourceEpoch: key.SourceEpoch, FromSeq: a.From})
			if err == nil {
				if prior.ToSeq != a.To || prior.Reason != a.Reason || prior.RangeDigest != a.Digest {
					ack.Rejected = append(ack.Rejected, conflict(rangeID))
				}
				continue // the same declaration again reuses its gap
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			overlaps, err := q.RangeOverlaps(ctx, netpoldb.RangeOverlapsParams{NodeUid: key.NodeUid, SourceEpoch: key.SourceEpoch, FromSeq: a.From, ToSeq: a.To})
			if err != nil {
				return err
			}
			if a.From <= current.AckedThrough || overlaps {
				ack.Rejected = append(ack.Rejected, conflict(rangeID))
				continue
			}
			start := current.AckedSourceTime
			if !start.Valid {
				start = clock
			}
			refs := []string{"netpol-range:" + rangeID}
			raw, _ := json.Marshal(refs)
			gap, err := q.InsertGap(ctx, netpoldb.InsertGapParams{Reason: "SEQUENCE_RANGE_ABANDONED", NodeUid: key.NodeUid, BootID: boot, SourceEpoch: b.SourceEpoch,
				SequenceFrom: pgtype.Int8{Int64: a.From, Valid: true}, SequenceTo: pgtype.Int8{Int64: a.To, Valid: true}, RangeDigest: pgtype.Text{String: a.Digest, Valid: true},
				StartAt: start, EndAt: clock, LossCount: pgtype.Int8{Int64: a.To - a.From + 1, Valid: true}, CountQuality: "exact", EvidenceRefs: raw})
			if err != nil {
				return err
			}
			if err := q.InsertAbandoned(ctx, netpoldb.InsertAbandonedParams{NodeUid: key.NodeUid, SourceEpoch: key.SourceEpoch, FromSeq: a.From, ToSeq: a.To,
				Reason: a.Reason, RangeDigest: a.Digest, GapID: gap}); err != nil {
				return err
			}
			gapID := uuid.UUID(gap.Bytes)
			if err := s.auditAs(ctx, q, CollectorActor, "sequence_range_abandoned", map[string]any{"source_id": CollectorSAN, "stream": "network_policy", "source_epoch": b.SourceEpoch, "range": map[string]any{"from_seq": a.From, "to_seq": a.To},
				"reason": a.Reason, "range_digest": a.Digest}, refs, clock.Time); err != nil {
				return err
			}
			if err := s.auditAs(ctx, q, CollectorActor, "observation_gap_recorded", map[string]any{"gap_id": gapID.String(), "stage": "network_policy_log", "reason": "SEQUENCE_RANGE_ABANDONED",
				"sequence_range": map[string]any{"from_seq": a.From, "to_seq": a.To}, "count_quality": "exact"}, refs, clock.Time); err != nil {
				return err
			}
			ack.LossGapIDs = append(ack.LossGapIDs, gapID)
		}
		acked, ackedTime := current.AckedThrough, current.AckedSourceTime
		rows, err := q.CoverageAfter(ctx, netpoldb.CoverageAfterParams{NodeUid: key.NodeUid, SourceEpoch: key.SourceEpoch, After: acked})
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.FromSeq > acked+1 {
				break
			}
			if row.ToSeq > acked {
				acked = row.ToSeq
				if row.SourceTime.Valid {
					ackedTime = row.SourceTime
				}
			}
		}
		var flushThrough pgtype.Int8
		var flushAt pgtype.Timestamptz
		if f := b.FinalFlush; f != nil && f.ThroughSequence >= 1 && acked >= f.ThroughSequence {
			flushThrough, flushAt = pgtype.Int8{Int64: f.ThroughSequence, Valid: true}, pgTime(f.CaughtUpAt)
			ack.FinalFlushRecorded = true
		}
		if err := q.UpsertWatermark(ctx, netpoldb.UpsertWatermarkParams{NodeUid: key.NodeUid, SourceEpoch: key.SourceEpoch, AckedThrough: acked,
			AckedSourceTime: ackedTime, FinalFlushThrough: flushThrough, FinalFlushCaughtUpAt: flushAt}); err != nil {
			return err
		}
		ack.AckedThrough = acked
		if l := b.RotationLoss; l != nil {
			if err := s.rotationLoss(ctx, q, node, boot, b.SourceEpoch, *l, clock.Time, &ack); err != nil {
				return err
			}
		}
		// caught_up_at proves the collector read to the file end only when every
		// stored sequence of every epoch of the node is contiguously
		// acknowledged; an older epoch with a hole keeps the gap open.
		if b.CaughtUpAt == nil {
			return nil
		}
		contiguous, err := q.EpochsContiguous(ctx, key.NodeUid)
		if err != nil {
			return err
		}
		if !contiguous.Valid || !contiguous.Bool {
			return nil
		}
		gaps, err := q.OpenCollectorGaps(ctx, sourceID)
		if err != nil {
			return err
		}
		for _, g := range gaps {
			if g.StartAt.Time.After(*b.CaughtUpAt) {
				continue
			}
			rng, err := q.SequenceRange(ctx, netpoldb.SequenceRangeParams{NodeUid: key.NodeUid, SourceEpoch: key.SourceEpoch, StartAt: g.StartAt, EndAt: pgTime(*b.CaughtUpAt)})
			if err != nil {
				return err
			}
			refs := []string{}
			if len(g.EvidenceRefs) > 0 {
				if err := json.Unmarshal(g.EvidenceRefs, &refs); err != nil {
					return err
				}
			}
			if rng.SequenceTo > 0 {
				refs = append(refs, fmt.Sprintf("netpol-sequence:%s:%d-%d", b.SourceEpoch, rng.SequenceFrom, rng.SequenceTo))
			}
			raw, _ := json.Marshal(refs)
			changed, err := q.BackfillGap(ctx, netpoldb.BackfillGapParams{EndAt: pgTime(*b.CaughtUpAt), EvidenceRefs: raw, GapID: g.GapID})
			if err != nil {
				return err
			}
			if changed != 1 {
				return errors.New("collector gap changed concurrently")
			}
			gapID := uuid.UUID(g.GapID.Bytes)
			if err := s.audit(ctx, q, "evidence_gap_resolved", map[string]any{"gap_id": gapID.String(), "recovery_state": "backfilled", "evidence_refs": refs}, refs, clock.Time); err != nil {
				return err
			}
			ack.BackfilledGapIDs = append(ack.BackfilledGapIDs, gapID)
		}
		return nil
	})
	return ack, err
}

// rotationLoss records the NETPOL_FILE_ROTATION_LOSS gap once per declaration
// and closes the open collector-stopped gap: partially_recovered when records
// after its start were read, unrecoverable otherwise.
func (s Store) rotationLoss(ctx context.Context, q *netpoldb.Queries, node NodeIdentity, boot pgtype.Text, epoch string, l RotationLoss, now time.Time, ack *Ack) error {
	nodeID := pgUUID(node.NodeUID)
	sourceID := "netpol-node/" + node.NodeUID.String()
	if _, err := q.RotationLossAt(ctx, netpoldb.RotationLossAtParams{NodeUid: nodeID, SourceEpoch: epoch, AfterSequence: l.AfterSequence}); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	refs := []string{fmt.Sprintf("netpol-rotation:%s:%d", epoch, l.AfterSequence)}
	start, err := q.NodeAckedSourceTime(ctx, nodeID)
	if err != nil {
		return err
	}
	if !start.Valid {
		if start, err = q.FirstLease(ctx, sourceID); err != nil {
			return err
		}
		refs = append(refs, "start_at:first_lease")
	}
	end := pgTime(l.DetectedAt)
	if !start.Valid || start.Time.After(l.DetectedAt) {
		// No earlier bound is known; the gap cannot start after it was seen.
		start = end
	}
	raw, _ := json.Marshal(refs)
	gap, err := q.InsertGap(ctx, netpoldb.InsertGapParams{Reason: "NETPOL_FILE_ROTATION_LOSS", NodeUid: nodeID, BootID: boot, SourceEpoch: epoch,
		StartAt: start, EndAt: end, CountQuality: "unknown", EvidenceRefs: raw})
	if err != nil {
		return err
	}
	if err := q.InsertRotationLoss(ctx, netpoldb.InsertRotationLossParams{NodeUid: nodeID, SourceEpoch: epoch, AfterSequence: l.AfterSequence, DetectedAt: end, GapID: gap}); err != nil {
		return err
	}
	gapID := uuid.UUID(gap.Bytes)
	if err := s.auditAs(ctx, q, CollectorActor, "observation_gap_recorded", map[string]any{"gap_id": gapID.String(), "stage": "network_policy_log", "reason": "NETPOL_FILE_ROTATION_LOSS", "count_quality": "unknown"}, refs, now); err != nil {
		return err
	}
	ack.LossGapIDs = append(ack.LossGapIDs, gapID)
	open, err := q.OpenCollectorGaps(ctx, sourceID)
	if err != nil {
		return err
	}
	for _, g := range open {
		read, err := q.RecordsSince(ctx, netpoldb.RecordsSinceParams{NodeUid: nodeID, Since: g.StartAt})
		if err != nil {
			return err
		}
		state := "unrecoverable"
		if read {
			state = "partially_recovered"
		}
		closeRefs := []string{}
		if len(g.EvidenceRefs) > 0 {
			if err := json.Unmarshal(g.EvidenceRefs, &closeRefs); err != nil {
				return err
			}
		}
		closeRefs = append(closeRefs, "gap:"+gapID.String())
		closeAt := end
		if g.StartAt.Time.After(l.DetectedAt) {
			closeAt = g.StartAt
		}
		rawRefs, _ := json.Marshal(closeRefs)
		changed, err := q.CloseGap(ctx, netpoldb.CloseGapParams{EndAt: closeAt, RecoveryState: state, EvidenceRefs: rawRefs, GapID: g.GapID})
		if err != nil {
			return err
		}
		if changed != 1 {
			return errors.New("collector gap changed concurrently")
		}
		if err := s.audit(ctx, q, "evidence_gap_resolved", map[string]any{"gap_id": uuid.UUID(g.GapID.Bytes).String(), "recovery_state": state, "evidence_refs": closeRefs}, closeRefs, now); err != nil {
			return err
		}
	}
	return nil
}

// WorkloadResolver maps a historical Pod to its `<namespace>/<ksa>` workload.
// The DB holds no KSA for a Pod, so a verified adapter supplies it; nil means
// the workload is unknown and the finding stays unlinked.
type WorkloadResolver func(pod uuid.UUID) *string

// AllowTable reports whether a destination is in the workload's TASK-06 3.1
// allow table. Unknown workloads are never allowed.
type AllowTable func(workload *string, dest netip.Addr, port int) bool

var observedNamespaces = []string{"agent-exec", "agent-adapters"}

func singlePod(ids []pgtype.UUID) *uuid.UUID {
	if len(ids) != 1 || !ids[0].Valid {
		return nil
	}
	u := uuid.UUID(ids[0].Bytes)
	return &u
}

type group struct {
	connects []Connect
	records  []Record
	segment  Segment
}

// collect loads and converts node inputs in [from, to] plus any rows named by
// ids (prior finding inputs outside the window), grouped by merge key.
func (s Store) collect(ctx context.Context, q *netpoldb.Queries, node uuid.UUID, from, to time.Time, kernelIDs, recordIDs []pgtype.UUID, workloads WorkloadResolver, allowed AllowTable) (map[string]*group, []string, error) {
	kernel, err := q.KernelConnects(ctx, netpoldb.KernelConnectsParams{NodeUid: pgUUID(node), FromTime: pgTime(from), ToTime: pgTime(to), Ids: kernelIDs})
	if err != nil {
		return nil, nil, err
	}
	records, err := q.Records(ctx, netpoldb.RecordsParams{NodeUid: pgUUID(node), FromTime: pgTime(from), ToTime: pgTime(to), Ids: recordIDs})
	if err != nil {
		return nil, nil, err
	}
	groups := map[string]*group{}
	keys := []string{}
	add := func(key string) *group {
		if g, ok := groups[key]; ok {
			return g
		}
		groups[key] = &group{}
		keys = append(keys, key)
		return groups[key]
	}
	for _, k := range kernel {
		pod := singlePod(k.PodUids)
		if pod == nil || !k.Dport.Valid {
			continue // without a unique historical Pod the source is not an observed Pod
		}
		ident, err := q.PodIdentity(ctx, pgUUID(*pod))
		if err != nil || !slices.Contains(observedNamespaces, ident.Namespace) {
			continue
		}
		src, err1 := netip.ParseAddr(k.Saddr)
		dest, err2 := netip.ParseAddr(k.Daddr)
		if err1 != nil || err2 != nil {
			continue
		}
		port := int(k.Dport.Int32)
		workload := workloads(*pod)
		c := Connect{KernelEventID: uuid.UUID(k.SourceEventID.Bytes), SourceTime: k.SourceTime.Time, NodeUID: node, PodUID: pod, PodNamespace: ident.Namespace,
			PodName: ident.PodName, WorkloadID: workload, SrcIP: src, DestIP: dest, DestPort: port, Established: k.Established,
			AdapterMatched: k.AdapterMatched, DestinationAllowed: allowed(workload, dest, port)}
		g := add(MergeKey(pod, src, dest, &port, "tcp"))
		g.connects = append(g.connects, c)
		if g.segment.NetworkSegment == "" {
			g.segment = s.Classifier.Classify(Endpoint{Namespace: ident.Namespace, PodName: ident.PodName}, dest.String(), Endpoint{})
		}
	}
	for _, r := range records {
		var src, dest EndpointRef
		if len(r.SrcEndpoint) > 0 {
			_ = json.Unmarshal(r.SrcEndpoint, &src)
		}
		if len(r.DestEndpoint) > 0 {
			_ = json.Unmarshal(r.DestEndpoint, &dest)
		}
		if src.Namespace == nil || !slices.Contains(observedNamespaces, *src.Namespace) || r.Direction != "egress" {
			continue
		}
		var port *int
		if r.DestPort.Valid {
			p := int(r.DestPort.Int32)
			port = &p
		}
		pod := singlePod(r.PodUids)
		var workload *string
		if pod != nil {
			workload = workloads(*pod)
		}
		rec := Record{RecordID: uuid.UUID(r.RecordID.Bytes), SourceTime: r.SourceTime.Time, NodeUID: node, Disposition: r.Disposition, Protocol: r.Protocol,
			SrcIP: r.SrcIp, DestIP: r.DestIp, DestPort: port, SrcNamespace: *src.Namespace, PodUID: pod, WorkloadID: workload, Count: int(r.Count)}
		if src.PodName != nil {
			rec.SrcPodName = *src.PodName
		}
		if dest.Namespace != nil {
			rec.DestNamespace = *dest.Namespace
		}
		if len(r.Policies) > 0 {
			var ps []PolicyRef
			_ = json.Unmarshal(r.Policies, &ps)
			for _, p := range ps {
				rec.PolicyNames = append(rec.PolicyNames, p.Namespace+"/"+p.Name)
			}
		}
		g := add(MergeKey(pod, r.SrcIp, r.DestIp, port, r.Protocol))
		g.records = append(g.records, rec)
		// A policy record carries the destination namespace; it takes precedence.
		g.segment = s.Classifier.Classify(Endpoint{Namespace: rec.SrcNamespace, PodName: rec.SrcPodName}, r.DestIp.String(), Endpoint{Namespace: rec.DestNamespace})
	}
	slices.Sort(keys)
	return groups, keys, nil
}

// clusters splits one merge key's inputs where consecutive source times are
// more than MergeWindow apart, so a single evaluation applies the same
// merge window as separate evaluations would.
func clusters(g *group) []*group {
	type item struct {
		at time.Time
		c  *Connect
		r  *Record
	}
	items := []item{}
	for i := range g.connects {
		items = append(items, item{at: g.connects[i].SourceTime, c: &g.connects[i]})
	}
	for i := range g.records {
		items = append(items, item{at: g.records[i].SourceTime, r: &g.records[i]})
	}
	slices.SortFunc(items, func(a, b item) int { return a.at.Compare(b.at) })
	out := []*group{}
	var cur *group
	var last time.Time
	for _, it := range items {
		if cur == nil || it.at.Sub(last) > MergeWindow {
			cur = &group{segment: g.segment}
			out = append(out, cur)
		}
		if it.c != nil {
			cur.connects = append(cur.connects, *it.c)
		} else {
			cur.records = append(cur.records, *it.r)
		}
		last = it.at
	}
	return out
}

// Evaluate judges node traffic whose source time is at least JudgeDelay old
// (relative to asOf) within [from, to], merges inputs into existing findings
// by merge key and time, and appends a revision only when the judgement
// changed. Each revision commits with its network_finding_recorded event.
func (s Store) Evaluate(ctx context.Context, node uuid.UUID, from, to, asOf time.Time, workloads WorkloadResolver, allowed AllowTable) ([]uuid.UUID, error) {
	if s.Classifier == nil || workloads == nil || allowed == nil {
		return nil, errors.New("classifier, workload resolver and allow table required")
	}
	if limit := asOf.Add(-JudgeDelay); to.After(limit) {
		to = limit
	}
	if !to.After(from) {
		return []uuid.UUID{}, nil
	}
	q := netpoldb.New(s.Pool)
	lo, hi := from.Add(-MatchWindow), to.Add(MatchWindow)
	groups, keys, err := s.collect(ctx, q, node, lo, hi, []pgtype.UUID{}, []pgtype.UUID{}, workloads, allowed)
	if err != nil {
		return nil, err
	}
	gapRows, err := q.NodeGaps(ctx, netpoldb.NodeGapsParams{NodeUid: pgUUID(node), FromTime: pgTime(lo), ToTime: pgTime(hi)})
	if err != nil {
		return nil, err
	}
	gaps := Context{}
	for _, g := range gapRows {
		switch {
		case g.Stage == "network_policy_log" && g.RecoveryState != "backfilled":
			gaps.LogGapOpen = true
		case g.Stage == "kernel_sensor_export":
			gaps.SensorGapIDs = append(gaps.SensorGapIDs, uuid.UUID(g.GapID.Bytes).String())
		}
	}
	// Prior finding inputs outside the window are reloaded by ID, so a
	// finding whose window grew never stalls the evaluation.
	loadPrior := func(key string, kernelIDs, recordIDs []pgtype.UUID) (*group, error) {
		epoch := time.Unix(0, 0)
		extra, _, err := s.collect(ctx, q, node, epoch, epoch, kernelIDs, recordIDs, workloads, allowed)
		if err != nil {
			return nil, err
		}
		if g, ok := extra[key]; ok {
			return g, nil
		}
		return &group{}, nil
	}
	written := []uuid.UUID{}
	var errs error
	for _, key := range keys {
		for _, g := range clusters(groups[key]) {
			id, changed, err := s.record(ctx, key, g.connects, g.records, g.segment, gaps, loadPrior)
			if err != nil {
				errs = errors.Join(errs, err) // one key's failure does not stop the others
				continue
			}
			if changed {
				written = append(written, id)
			}
		}
	}
	return written, errs
}

func idStrings(ids []uuid.UUID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

func pgIDs(ids []uuid.UUID) []pgtype.UUID {
	out := make([]pgtype.UUID, 0, len(ids))
	for _, id := range ids {
		out = append(out, pgUUID(id))
	}
	return out
}

func fromPgIDs(ids []pgtype.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		out = append(out, uuid.UUID(id.Bytes))
	}
	return out
}

// record merges one group into the latest finding of its merge key whose
// window covers the inputs, re-judges the full ID set and appends a revision
// when the content changed.
func (s Store) record(ctx context.Context, key string, connects []Connect, records []Record, seg Segment, gaps Context, loadPrior func(string, []pgtype.UUID, []pgtype.UUID) (*group, error)) (uuid.UUID, bool, error) {
	var id uuid.UUID
	changed := false
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		q := netpoldb.New(tx)
		if err := q.LimitLockWait(ctx); err != nil {
			return err
		}
		if err := q.LockKey(ctx, "correlation/netfinding/"+key); err != nil {
			return err
		}
		var earliest time.Time
		for _, c := range connects {
			if earliest.IsZero() || c.SourceTime.Before(earliest) {
				earliest = c.SourceTime
			}
		}
		for _, r := range records {
			if earliest.IsZero() || r.SourceTime.Before(earliest) {
				earliest = r.SourceTime
			}
		}
		latest, err := q.FindingsByMergeKey(ctx, key)
		if err != nil {
			return err
		}
		var prior *netpoldb.CorrelationNetworkFindingsLatest
		for i := range latest {
			f := latest[i]
			if !earliest.Before(f.WindowStart.Time.Add(-MatchWindow)) && !earliest.After(f.WindowEnd.Time.Add(MergeWindow)) {
				prior = &f
				break // ordered by window_end DESC: the latest-ending finding wins
			}
		}
		if prior != nil {
			// Re-judge the union with the prior revision's source IDs; inputs
			// outside the evaluated window are reloaded by ID.
			seenK := map[uuid.UUID]bool{}
			for _, c := range connects {
				seenK[c.KernelEventID] = true
			}
			seenR := map[uuid.UUID]bool{}
			for _, r := range records {
				seenR[r.RecordID] = true
			}
			missingK, missingR := []pgtype.UUID{}, []pgtype.UUID{}
			for _, k := range prior.KernelEventIds {
				if !seenK[k.Bytes] {
					missingK = append(missingK, k)
				}
			}
			for _, r := range prior.PolicyRecordIds {
				if !seenR[r.Bytes] {
					missingR = append(missingR, r)
				}
			}
			if len(missingK)+len(missingR) > 0 {
				extra, err := loadPrior(key, missingK, missingR)
				if err != nil {
					return err
				}
				if len(extra.connects)+len(extra.records) != len(missingK)+len(missingR) {
					return fmt.Errorf("finding %s inputs are no longer attributable to this key", uuid.UUID(prior.FindingID.Bytes))
				}
				connects = append(slices.Clone(connects), extra.connects...)
				records = append(slices.Clone(records), extra.records...)
			}
		}
		j, ok := Judge(connects, records, gaps)
		if !ok {
			return nil // no finding is defined; a prior revision is preserved as is
		}
		limits := slices.Clone(j.Limitations)
		for _, l := range seg.Limitations {
			limits = addLimit(limits, l)
		}
		slices.Sort(limits)
		reason := j.Reason + "; segment: " + seg.Reason
		revision := int32(1)
		id = uuid.New()
		if prior != nil {
			id, revision = uuid.UUID(prior.FindingID.Bytes), prior.Revision+1
			if prior.Kind != j.Kind {
				reason = "kind changed from " + prior.Kind + ": " + reason
			}
			same := prior.Kind == j.Kind && prior.Outcome == j.Outcome && slices.Equal(fromPgIDs(prior.KernelEventIds), j.KernelEventIDs) &&
				slices.Equal(fromPgIDs(prior.PolicyRecordIds), j.PolicyRecordIDs) && slices.Equal(prior.Limitations, limits) &&
				prior.WindowStart.Time.Equal(j.WindowStart) && prior.WindowEnd.Time.Equal(j.WindowEnd)
			if same {
				return nil
			}
		}
		var attempts pgtype.Int8
		if j.AttemptCount != nil {
			attempts = pgtype.Int8{Int64: *j.AttemptCount, Valid: true}
		}
		var workload pgtype.Text
		if j.WorkloadID != nil {
			workload = pgtype.Text{String: *j.WorkloadID, Valid: true}
		}
		var pod pgtype.UUID
		if j.PodUID != nil {
			pod = pgUUID(*j.PodUID)
		}
		created, err := q.InsertFinding(ctx, netpoldb.InsertFindingParams{FindingID: pgUUID(id), Revision: revision, Kind: j.Kind, Outcome: j.Outcome,
			NetworkSegment: seg.NetworkSegment, BoundaryCrossing: seg.BoundaryCrossing, WorkloadID: workload, PodUid: pod, NodeUid: pgUUID(j.NodeUID),
			MergeKey: key, KernelEventIds: pgIDs(j.KernelEventIDs), PolicyRecordIds: pgIDs(j.PolicyRecordIDs), WindowStart: pgTime(j.WindowStart),
			WindowEnd: pgTime(j.WindowEnd), AttemptCount: attempts, CountQuality: j.CountQuality, Confidence: j.Confidence,
			RuleVersion: RuleVersion, AlgorithmVersion: AlgorithmVersion, Reason: reason, Limitations: limits})
		if err != nil {
			return err
		}
		payload := map[string]any{"finding_id": id.String(), "revision": revision, "kind": j.Kind, "outcome": j.Outcome, "network_segment": seg.NetworkSegment,
			"boundary_crossing": seg.BoundaryCrossing, "confidence": j.Confidence, "rule_version": RuleVersion, "algorithm_version": AlgorithmVersion}
		if j.WorkloadID != nil {
			payload["workload_id"] = *j.WorkloadID
		}
		refs := append(idStrings(j.KernelEventIDs), idStrings(j.PolicyRecordIDs)...)
		if err := s.audit(ctx, q, "network_finding_recorded", payload, refs, created.Time); err != nil {
			return err
		}
		changed = true
		return nil
	})
	return id, changed, err
}
