package probes

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// eventsQuery rebuilds the checked KernelEvent fields from audit.kernel_events
// (TASK-07). The stored row has no raw record, so record_digest is compared to
// the WAL copy when both exist instead of being recomputed.
const eventsQuery = `
SELECT json_build_object(
  'source_event_id', source_event_id, 'sensor_id', sensor_id, 'source_epoch', source_epoch,
  'source_sequence', source_sequence,
  'source_time', to_char(source_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'event_type', event_type, 'pod_uid', pod_uid, 'container_id', container_id,
  'socket_tuple', CASE WHEN saddr IS NULL THEN NULL ELSE json_build_object('saddr', host(saddr), 'sport', sport, 'daddr', host(daddr), 'dport', dport) END,
  'sock_ptr', sock_ptr, 'tcp_new_state', tcp_new_state, 'safe_attributes', safe_attributes,
  'record_digest', record_digest)::text
FROM audit.kernel_events
WHERE node_uid = $1 AND source_time BETWEEN $2 AND $3
ORDER BY source_epoch, source_sequence`

// QueryEvents reads the stored KernelEvents of one node and time window
// through a read-only session.
func QueryEvents(ctx context.Context, conn *pgx.Conn, nodeUID string, from, to time.Time) ([]Event, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, eventsQuery, nodeUID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, err
		}
		var e Event
		if err := json.Unmarshal([]byte(text), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
