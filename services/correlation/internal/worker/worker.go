// Package worker is the TASK-10 3.1 correlation consumer: it reads stored
// kernel connects/state transitions, derived lifecycle intervals, TASK-03
// attempt observations and Q0 normalization rules from PostgreSQL, runs the
// pure join engine and appends correlation revisions with their audit event.
package worker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/join"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/results"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/worker/workerdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Method is stored in correlation.method for join-derived revisions. COMMON
// defines no method enum; this names the 3.1 socket join.
const Method = "kernel_socket_join"

// lateStateWindow bounds how long after a connect an ESTABLISHED transition
// is searched (the join itself enforces send_started_at + 2s).
const lateStateWindow = 5 * time.Minute

// WorkloadResolver maps a historical Pod to its `<namespace>/<ksa>` workload
// from verified evidence. nil leaves the interval out, so its events stay
// unlinked; the database stores no KSA for a Pod.
type WorkloadResolver func(pod uuid.UUID) *string

type Worker struct {
	Pool             *pgxpool.Pool
	Results          results.Store
	ClusterUID       uuid.UUID
	AlgorithmVersion string
	Workloads        WorkloadResolver
}

// MinDelay is how old a window must be before it is correlated: kernel and
// lifecycle ingest lag (10s) plus the 60s TASK-03 outcome recording margin.
// A risk evaluator must read the latest revision after this delay.
const MinDelay = 60 * time.Second

func addrPort(addr string, port pgtype.Int4) (netip.AddrPort, bool) {
	a, err := netip.ParseAddr(addr)
	// The join rejects unspecified addresses; such a row is skipped, never
	// allowed to fail the whole snapshot.
	if err != nil || !port.Valid || port.Int32 <= 0 || port.Int32 > 65535 || a.IsUnspecified() || a.Zone() != "" {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a, uint16(port.Int32)), true
}

func sockPtr(hex string) (uint64, bool) {
	v, err := strconv.ParseUint(hex, 16, 64)
	return v, err == nil && len(hex) == 16
}

// Run correlates every tcp_connect of node with source_time in [from, to).
// The snapshot extends to all observation windows overlapping the range so
// uniqueness is judged over every candidate, not a trimmed singleton. It
// returns the number of new revisions.
func (w Worker) Run(ctx context.Context, node uuid.UUID, from, to, asOf time.Time) (int, error) {
	if w.Pool == nil || w.ClusterUID == uuid.Nil || w.AlgorithmVersion == "" || w.Workloads == nil {
		return 0, errors.New("pool, cluster, algorithm version and workload resolver required")
	}
	if limit := asOf.Add(-MinDelay); to.After(limit) {
		to = limit
	}
	if !to.After(from) {
		return 0, nil
	}
	q := workerdb.New(w.Pool)
	pgTime := func(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
	obs, err := q.Observations(ctx, workerdb.ObservationsParams{NodeUid: pgtype.UUID{Bytes: node, Valid: true}, FromTime: pgTime(from.Add(-join.ClockSkew)), ToTime: pgTime(to.Add(join.ClockSkew))})
	if err != nil {
		return 0, err
	}
	lo, hi := from, to
	snapshot := join.Snapshot{ClusterUID: w.ClusterUID.String(), AlgorithmVersion: w.AlgorithmVersion}
	for _, o := range obs {
		local, ok1 := addrPort(o.LocalAddr, o.LocalPort)
		peer, ok2 := addrPort(o.PeerAddr, o.PeerPort)
		if !ok1 || !ok2 || !o.NetnsInode.Valid || o.NetnsInode.Int64 <= 0 || o.SendStartedAt.Time.Before(o.ConnectStartedAt.Time) {
			continue
		}
		start, send := o.ConnectStartedAt.Time, o.SendStartedAt.Time
		if start.Add(-join.ClockSkew).Before(lo) {
			lo = start.Add(-join.ClockSkew)
		}
		if send.Add(join.ClockSkew).After(hi) {
			hi = send.Add(join.ClockSkew)
		}
		snapshot.Observations = append(snapshot.Observations, join.Observation{AttemptID: uuid.UUID(o.AttemptID.Bytes).String(), ActionID: uuid.UUID(o.ActionID.Bytes).String(),
			PodUID: uuid.UUID(o.PodUid.Bytes).String(), NetNS: uint64(o.NetnsInode.Int64), Tuple: join.Tuple{Local: local, Peer: peer}, ConnectStartedAt: start, SendStartedAt: send})
	}
	nodeID := pgtype.UUID{Bytes: node, Valid: true}
	connects, err := q.Connects(ctx, workerdb.ConnectsParams{NodeUid: nodeID, FromTime: pgTime(lo), ToTime: pgTime(hi.Add(time.Microsecond))})
	if err != nil {
		return 0, err
	}
	targets := map[string]bool{}
	unresolved := map[string]bool{}
	var untracked []join.Result
	for _, c := range connects {
		id := uuid.UUID(c.SourceEventID.Bytes).String()
		inRange := !c.SourceTime.Time.Before(from) && c.SourceTime.Time.Before(to)
		local, ok1 := addrPort(c.Saddr, c.Sport)
		peer, ok2 := addrPort(c.Daddr, c.Dport)
		var ptr uint64
		ok3 := true
		if c.SockPtr != "" {
			ptr, ok3 = sockPtr(c.SockPtr)
		}
		if !ok1 || !ok2 || !ok3 {
			// Still recorded: an unusable socket identity is an unlinked result,
			// never a silently missing one.
			if inRange {
				untracked = append(untracked, join.Result{KernelEventID: id, Confidence: join.Unlinked, AlgorithmVersion: w.AlgorithmVersion,
					Diagnostic: "socket tuple or sock_ptr unusable", Limitations: []string{}, EvidenceRefs: []string{}})
			}
			continue
		}
		snapshot.Connects = append(snapshot.Connects, join.Connect{EventID: id, NodeUID: node.String(), BootID: c.BootID, ContainerID: c.ContainerID,
			ProcessExecID: c.ProcessExecID, PodUID: c.PodUid, NetNS: uint64(c.NetnsInode), SockPtr: ptr, SourceTime: c.SourceTime.Time, Tuple: join.Tuple{Local: local, Peer: peer}})
		if inRange {
			targets[id] = true
			if c.ContainerID == "" {
				unresolved[id] = true
			}
		}
	}
	states, err := q.States(ctx, workerdb.StatesParams{NodeUid: nodeID, FromTime: pgTime(lo), ToTime: pgTime(hi.Add(lateStateWindow))})
	if err != nil {
		return 0, err
	}
	for _, s := range states {
		local, ok1 := addrPort(s.Saddr, s.Sport)
		peer, ok2 := addrPort(s.Daddr, s.Dport)
		ptr, ok3 := sockPtr(s.SockPtr)
		if !ok1 || !ok2 || !ok3 || !s.TcpNewState.Valid {
			continue
		}
		state := map[int16]string{1: "ESTABLISHED", 7: "CLOSE"}[s.TcpNewState.Int16]
		if state == "" {
			continue
		}
		snapshot.States = append(snapshot.States, join.State{EventID: uuid.UUID(s.SourceEventID.Bytes).String(), NodeUID: node.String(), BootID: s.BootID,
			SockPtr: ptr, SourceTime: s.SourceTime.Time, Tuple: join.Tuple{Local: local, Peer: peer}, NewState: state})
	}
	intervals, err := q.Intervals(ctx, nodeID)
	if err != nil {
		return 0, err
	}
	// An interval that cannot prove its mapping (no start, no verified
	// workload) makes its whole container ambiguous instead of being dropped,
	// so a remaining interval never looks like a unique mapping.
	ambiguous := map[string]bool{}
	for _, i := range intervals {
		key := i.BootID + "/" + i.ContainerID
		if i.ClusterUid.Bytes != w.ClusterUID {
			continue
		}
		if i.EndedAt.Valid && i.EndedAt.Time.Before(lo) || i.StartedAt.Valid && i.StartedAt.Time.After(hi) {
			continue
		}
		if !i.StartedAt.Valid || validWorkload(w.Workloads(uuid.UUID(i.PodUid.Bytes))) == "" {
			ambiguous[key] = true
		}
	}
	for _, i := range intervals {
		if i.ClusterUid.Bytes != w.ClusterUID || ambiguous[i.BootID+"/"+i.ContainerID] || !i.StartedAt.Valid {
			continue
		}
		if i.EndedAt.Valid && i.EndedAt.Time.Before(lo) || i.StartedAt.Time.After(hi) {
			continue
		}
		workload := validWorkload(w.Workloads(uuid.UUID(i.PodUid.Bytes)))
		var ended *time.Time
		if i.EndedAt.Valid {
			t := i.EndedAt.Time
			ended = &t
		}
		refs := []string{}
		for _, e := range i.SourceEventIds {
			refs = append(refs, "lifecycle_event:"+uuid.UUID(e.Bytes).String())
		}
		snapshot.Lifecycles = append(snapshot.Lifecycles, join.Lifecycle{IntervalID: "lifecycle_interval:" + uuid.UUID(i.IntervalID.Bytes).String(), ClusterUID: w.ClusterUID.String(),
			NodeUID: node.String(), BootID: i.BootID, ContainerID: i.ContainerID, PodUID: uuid.UUID(i.PodUid.Bytes).String(), WorkloadID: workload,
			StartedAt: i.StartedAt.Time, EndedAt: ended, EndQuality: i.EndQuality, EvidenceRefs: refs})
	}
	rules, err := q.Rules(ctx, w.AlgorithmVersion)
	if err != nil {
		return 0, err
	}
	for _, r := range rules {
		vip, err1 := netip.ParseAddr(r.ServiceVip)
		cidr, err2 := netip.ParsePrefix(r.EndpointCidr)
		if err1 != nil || err2 != nil {
			return 0, fmt.Errorf("invalid stored normalization rule %s", r.EndpointCidr)
		}
		snapshot.Rules = append(snapshot.Rules, join.Rule{AlgorithmVersion: r.AlgorithmVersion, MeasuredRunID: r.MeasuredRunID, Service: netip.AddrPortFrom(vip, uint16(r.ServicePort)),
			EndpointCIDR: cidr, EndpointPort: uint16(r.EndpointPort), KernelSide: join.Side(r.KernelSide), AdapterSide: join.Side(r.AdapterSide)})
	}
	prefixes := map[string]string{}
	for _, c := range snapshot.Connects {
		prefixes[c.EventID] = "kernel_event:"
	}
	for _, s := range snapshot.States {
		prefixes[s.EventID] = "kernel_event:"
	}
	for _, o := range snapshot.Observations {
		prefixes[o.AttemptID] = "attempt:"
	}
	for _, r := range snapshot.Rules {
		prefixes[r.MeasuredRunID] = "q0_run:"
	}
	computed, err := join.Match(snapshot)
	if err != nil {
		return 0, err
	}
	written := 0
	computed = append(computed, untracked...)
	for _, c := range computed {
		if unresolved[c.KernelEventID] && c.Confidence == join.Unlinked {
			// #160: the exporter left container/Pod metadata unresolved; keep the
			// reason so a late lifecycle record can be re-evaluated.
			c.Diagnostic = "kernel metadata unresolved (no container_id)"
			c.Limitations = append(c.Limitations, "metadata_unresolved")
		}
		if !targets[c.KernelEventID] {
			continue
		}
		in, err := toResult(c, prefixes)
		if err != nil {
			return written, err
		}
		created, err := w.appendLatest(ctx, in)
		if err != nil {
			return written, err
		}
		if created {
			written++
		}
	}
	return written, nil
}

// validWorkload returns the resolver's `<namespace>/<ksa>` only when it has
// that exact shape; anything else is treated as unknown.
func validWorkload(w *string) string {
	if w == nil {
		return ""
	}
	parts := strings.Split(*w, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return *w
}

// toResult translates the engine result into documented correlation columns.
// Only confirmed results carry attempt/action identity.
func toResult(c join.Result, prefixes map[string]string) (results.Result, error) {
	kernel, err := uuid.Parse(c.KernelEventID)
	if err != nil {
		return results.Result{}, err
	}
	refs := []string{"kernel_event:" + kernel.String()}
	for _, ref := range c.EvidenceRefs {
		// The engine reports bare kernel event and attempt IDs; type them.
		refs = append(refs, prefixes[ref]+ref)
	}
	out := results.Result{KernelEventID: kernel, Confidence: string(c.Confidence), Method: Method, AlgorithmVersion: c.AlgorithmVersion,
		Reason: c.Diagnostic, EvidenceRefs: refs, CandidateCount: int32(c.CandidateCount), Limitations: append([]string{}, c.Limitations...)}
	if out.Reason == "" {
		out.Reason = "no verified historical mapping"
	}
	if c.WorkloadID != "" {
		w := c.WorkloadID
		out.WorkloadID = &w
	}
	if out.Reason == "" {
		out.Reason = "no verified historical mapping"
	}
	if c.Attribution != nil {
		attempt, err1 := uuid.Parse(c.Attribution.AttemptID)
		action, err2 := uuid.Parse(c.Attribution.ActionID)
		if err1 != nil || err2 != nil {
			return results.Result{}, errors.New("invalid confirmed attribution")
		}
		out.AttemptID, out.ActionID = &attempt, &action
		out.EvidenceRefs = append(out.EvidenceRefs, "process_exec:"+c.Attribution.ProcessExecID)
	}
	return out, nil
}

// appendLatest bases the calculation on the stored latest revision; one
// concurrent writer winning is retried once from the reloaded revision.
func (w Worker) appendLatest(ctx context.Context, in results.Result) (bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		var expected int32
		latest, err := w.Results.Latest(ctx, in.KernelEventID)
		switch {
		case err == nil:
			expected = latest.Revision
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return false, err
		}
		_, created, err := w.Results.Append(ctx, in, expected)
		if errors.Is(err, results.ErrStaleRevision) {
			continue
		}
		return created, err
	}
	return false, results.ErrStaleRevision
}
