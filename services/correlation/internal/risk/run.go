package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/risk/riskdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func pgUUID(u uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: u, Valid: true} }
func pgTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// WorkloadResolver maps a historical Pod to `<namespace>/<ksa>`; nil means
// the workload is not identified and no hold is requested.
type WorkloadResolver func(pod uuid.UUID) *string

// AllowTable reports whether the destination is in the workload's TASK-06 3.1
// allow table.
type AllowTable func(workload string, dest netip.Addr, port int) bool

// Load reads the node's risk candidates in [from, to) and the exec history
// needed for lineage from the TASK-07 correlation_reader grant.
func Load(ctx context.Context, pool *pgxpool.Pool, node uuid.UUID, from, to time.Time, workloads WorkloadResolver, allowed AllowTable) ([]Event, map[string]string, error) {
	q := riskdb.New(pool)
	nodeID := pgUUID(node)
	rows, err := q.Events(ctx, riskdb.EventsParams{NodeUid: nodeID, FromTime: pgTime(from), ToTime: pgTime(to)})
	if err != nil {
		return nil, nil, err
	}
	starts, err := q.Starts(ctx, riskdb.StartsParams{NodeUid: nodeID, FromTime: pgTime(from), ToTime: pgTime(to)})
	if err != nil {
		return nil, nil, err
	}
	// The container start process is bound to the lifecycle start: the
	// container's earliest observed exec counts only when it lies at the
	// interval's started_at. If the entrypoint exec was missed (sensor restart,
	// startup capture unsupported) no root is set and lineage stays
	// undetermined, so an injected exec never becomes the root (TASK-10 3.2).
	roots := map[string]string{}
	since := from
	for _, st := range starts {
		if st.StartedAt.Time.Before(since) {
			since = st.StartedAt.Time
		}
		if st.FirstExec != "" && st.FirstExecAt.Valid && StartsContainer(st.StartedAt.Time, st.FirstExecAt.Time) {
			roots[RootKey(node.String(), st.BootID, st.ContainerID)] = st.FirstExec
		}
	}
	execs, err := q.Execs(ctx, riskdb.ExecsParams{NodeUid: nodeID, FromTime: pgTime(since.Add(-StartSkew)), ToTime: pgTime(to)})
	if err != nil {
		return nil, nil, err
	}
	events := []Event{}
	for _, x := range execs {
		events = append(events, Event{ID: "", EventType: "process_exec", NodeUID: node.String(), BootID: x.BootID, ContainerID: x.ContainerID,
			ProcessExecID: x.ProcessExecID, ParentExecID: x.ParentExecID, SourceTime: x.SourceTime.Time})
	}
	for _, r := range rows {
		e := Event{ID: uuid.UUID(r.SourceEventID.Bytes).String(), EventType: r.EventType, NodeUID: node.String(), BootID: r.BootID, ContainerID: r.ContainerID,
			ProcessExecID: r.ProcessExecID, ParentExecID: r.ParentExecID, SourceTime: r.SourceTime.Time, Established: r.Established, Confirmed: r.Confirmed, Path: r.Path}
		if r.Flags >= 0 {
			f := r.Flags
			e.Flags = &f
		}
		if pod, err := uuid.Parse(r.PodUid); err == nil {
			e.WorkloadID = workloads(pod)
		}
		if r.EventType == "tcp_connect" && e.WorkloadID != nil {
			dest, err := netip.ParseAddr(r.Daddr)
			e.DestinationAllowed = err == nil && r.Dport.Valid && allowed(*e.WorkloadID, dest, int(r.Dport.Int32))
		}
		events = append(events, e)
	}
	return withoutHistory(events), roots, nil
}

// StartSkew and StartWindow bound the entrypoint exec around the lifecycle
// start (clock skew before, runtime start latency after). Initial values;
// TASK-09 Q0 measures the start latency.
const (
	StartSkew   = 2 * time.Second
	StartWindow = 5 * time.Second
)

// StartsContainer reports whether an exec at execAt is the start process of
// a container whose lifecycle interval started at startedAt.
func StartsContainer(startedAt, execAt time.Time) bool {
	return !execAt.Before(startedAt.Add(-StartSkew)) && !execAt.After(startedAt.Add(StartWindow))
}

// withoutHistory keeps exec history rows (empty ID) for parent lookup but
// marks them unattributed so they are never judged twice.
func withoutHistory(events []Event) []Event {
	for i := range events {
		if events[i].ID == "" {
			events[i].WorkloadID = nil
		}
	}
	return events
}

// HoldClient requests risk_event holds from control-health over mTLS with
// the correlation identity (component_principals allows only risk_event).
type HoldClient struct {
	URL    string
	Client *http.Client
}

type HoldAck struct {
	HoldID   *string  `json:"hold_id"`
	Decision string   `json:"decision"`
	Codes    []string `json:"reason_codes"`
}

var ErrRejected = errors.New("risk_event hold request rejected")

// Request sends one decision. A repeat for the same workload returns the open
// hold (decision existing); the server records the added kernel evidence.
func (c HoldClient) Request(ctx context.Context, d Decision) (HoldAck, error) {
	body, err := json.Marshal(map[string]any{"scope": "workload", "scope_id": d.WorkloadID, "reason": "risk_event", "reason_detail": d.Detail,
		"evidence_refs": []string{"kernel_event:" + d.KernelEventID}})
	if err != nil {
		return HoldAck{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/internal/holds", bytes.NewReader(body))
	if err != nil {
		return HoldAck{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return HoldAck{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return HoldAck{}, errors.New("invalid hold response")
	}
	var ack HoldAck
	if json.Unmarshal(raw, &ack) != nil {
		return HoldAck{}, errors.New("invalid hold response")
	}
	switch {
	case resp.StatusCode == http.StatusForbidden && ack.Decision == "rejected":
		return ack, ErrRejected
	case resp.StatusCode != http.StatusOK || ack.HoldID == nil || (ack.Decision != "created" && ack.Decision != "existing"):
		return ack, fmt.Errorf("hold request not accepted: HTTP %d", resp.StatusCode)
	}
	return ack, nil
}
