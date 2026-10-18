package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
)

// ExecuteRequest is the POST /internal/adapter/{adapter_id}/execute body
// (COMMON API implementation contract).
type ExecuteRequest struct {
	DecisionID string `json:"decision_id"`
	ActionID   string `json:"action_id"`
}

// executeAck is the adapter's 202 body.
type executeAck struct {
	DecisionID string `json:"decision_id"`
	ActionID   string `json:"action_id"`
	State      string `json:"state"`
}

// claimed is one execute_requests row taken by the worker.
type claimed struct {
	decisionID string
	actionID   string
	adapterID  string
	attempts   int
	expiresAt  time.Time
}

// RunWorker delivers execute_requests until ctx ends (TASK-04 3.5). It
// drains every due row, then waits for Kick or WorkerPoll.
func (s *Service) RunWorker(ctx context.Context) {
	t := time.NewTicker(WorkerPoll)
	defer t.Stop()
	for {
		for {
			worked, err := s.DeliverOnce(ctx)
			if err != nil {
				s.log().Error("execute delivery failed", "err", err)
				break
			}
			if !worked {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kickCh():
		}
	}
}

// DeliverOnce takes one due pending row with FOR UPDATE SKIP LOCKED and
// delivers it. It reports whether a row was taken.
//   - A row whose decision has expired becomes expired; the runtime starts
//     again with :reevaluate.
//   - Otherwise the row is claimed for ClaimLease (attempts + 1), the
//     transaction commits, and the adapter is called without holding a lock.
//   - 202 with the same decision_id and action_id makes it delivered. Any
//     other outcome schedules the next try 200 ms × 2^(attempts-1) later;
//     the decision TTL bounds the retries.
//
// The adapter ignores a repeated decision (adapter_executions, TASK-05), so
// a retry after a lost 202 is safe; this is an internal retry, not a retry
// of the external action.
func (s *Service) DeliverOnce(ctx context.Context) (bool, error) {
	var row *claimed
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var r claimed
		var expired bool
		err := tx.QueryRow(ctx, `
SELECT e.decision_id::text, e.action_id::text, e.adapter_id, e.attempts, d.expires_at, d.expires_at <= statement_timestamp()
FROM decisions.execute_requests e
JOIN decisions.decisions d USING (decision_id)
WHERE e.state = 'pending' AND e.next_attempt_at <= statement_timestamp()
  AND (e.lease_until IS NULL OR e.lease_until <= statement_timestamp())
ORDER BY e.next_attempt_at
LIMIT 1
FOR UPDATE OF e SKIP LOCKED`).Scan(&r.decisionID, &r.actionID, &r.adapterID, &r.attempts, &r.expiresAt, &expired)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if expired {
			_, err := tx.Exec(ctx, `
UPDATE decisions.execute_requests SET state = 'expired', lease_until = NULL, updated_at = statement_timestamp()
WHERE decision_id = $1`, r.decisionID)
			row = &claimed{} // worked, nothing to send
			return err
		}
		r.attempts++
		if _, err := tx.Exec(ctx, `
UPDATE decisions.execute_requests
SET attempts = $2, lease_until = statement_timestamp() + make_interval(secs => $3), updated_at = statement_timestamp()
WHERE decision_id = $1`, r.decisionID, r.attempts, ClaimLease.Seconds()); err != nil {
			return err
		}
		row = &r
		return nil
	})
	if err != nil || row == nil {
		return false, err
	}
	if row.decisionID == "" {
		return true, nil
	}
	callErr := s.callAdapter(ctx, row)
	if callErr == nil {
		return true, s.inTx(ctx, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `
UPDATE decisions.execute_requests SET state = 'delivered', lease_until = NULL, updated_at = statement_timestamp()
WHERE decision_id = $1 AND state = 'pending'`, row.decisionID)
			return err
		})
	}
	s.log().Warn("adapter execute failed", "decision_id", row.decisionID, "adapter_id", row.adapterID, "attempt", row.attempts, "err", callErr)
	backoff := FirstBackoff << (row.attempts - 1)
	if row.attempts > 16 {
		backoff = DecisionTTL
	}
	return true, s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
UPDATE decisions.execute_requests
SET next_attempt_at = statement_timestamp() + make_interval(secs => $2), lease_until = NULL, updated_at = statement_timestamp()
WHERE decision_id = $1 AND state = 'pending'`, row.decisionID, backoff.Seconds())
		return err
	})
}

// callAdapter POSTs {decision_id, action_id} to the adapter and accepts only
// 202 with the same IDs.
func (s *Service) callAdapter(ctx context.Context, r *claimed) error {
	if s.Adapter == nil {
		return ErrUnwired
	}
	ep, ok := s.Adapter(r.adapterID)
	if !ok || ep.BaseURL == "" || ep.Client == nil {
		return fmt.Errorf("no endpoint for adapter %q", r.adapterID)
	}
	body, err := json.Marshal(ExecuteRequest{DecisionID: r.decisionID, ActionID: r.actionID})
	if err != nil {
		return err
	}
	timeout := min(ExecuteTimeout, time.Until(r.expiresAt))
	if timeout <= 0 {
		return errors.New("decision expired before the call")
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost,
		ep.BaseURL+"/internal/adapter/"+url.PathEscape(r.adapterID)+"/execute", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := ep.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("adapter answered %d", resp.StatusCode)
	}
	var ack executeAck
	if err := strictInto(b, &ack); err != nil {
		return fmt.Errorf("adapter ack: %w", err)
	}
	if ack.DecisionID != r.decisionID || ack.ActionID != r.actionID {
		return errors.New("adapter ack names another decision")
	}
	return nil
}

// AdapterEndpoint is how the worker reaches one adapter: its base URL
// (https://host:port) and its client from NewAdapterClient.
type AdapterEndpoint struct {
	BaseURL string
	Client  *http.Client
}
