package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

// PeerIdentityHeader carries the caller SAN the gateway verified when it
// forwards a runtime request to an internal service (COMMON header table). The
// gateway always deletes the client's value and sets its own.
const PeerIdentityHeader = "X-Agentarium-Peer-Identity"

// ReadinessTimeout bounds one work-readiness lookup. SPEC-QUESTION: the
// specs give no value; it is below the 3 s maximum result age of a ready
// check (COMMON work_readiness.maximum_result_age_seconds).
const ReadinessTimeout = 2 * time.Second

const maxReadinessBody = 64 << 10

// HTTPReadiness checks a runtime's WorkReadinessCheck with TASK-10
// control-health: GET /internal/control-health/work-readiness/checks/{id},
// which only the gateway may call (COMMON internal API table), with the caller's
// verified SAN in X-Agentarium-Peer-Identity. control-health answers with the
// caller's own WorkReadinessCheck and remaining_valid_ms (COMMON 1332).
//
// The gateway then requires (TASK-04 work-start gate):
//   - the check's check_id, work_run_id, session_id, workload_id and
//     caller_identity are this request's, otherwise 403
//     WORK_READINESS_BINDING_MISMATCH;
//   - state ready with remaining validity, otherwise 503 (the check's first
//     reason code, or WORK_READINESS_EXPIRED).
//
// An unknown check (404) is not ready (503 WORK_READINESS_EXPIRED); a
// control-health 403 is a binding mismatch; any other failure is 503
// CONTROL_HEALTH_UNAVAILABLE. Nothing is ever treated as ready by default.
type HTTPReadiness struct {
	BaseURL string
	Client  *http.Client
}

type readinessCheck struct {
	CheckID          string   `json:"check_id"`
	WorkRunID        string   `json:"work_run_id"`
	SessionID        string   `json:"session_id"`
	WorkloadID       string   `json:"workload_id"`
	CallerIdentity   string   `json:"caller_identity"`
	State            string   `json:"state"`
	ReasonCodes      []string `json:"reason_codes"`
	RemainingValidMS *int64   `json:"remaining_valid_ms"`
}

// readinessNotReadyCodes are the WorkReadinessCheck.reason_codes the
// gateway passes through as its 503 code (COMMON enum table). Session and budget
// codes and anything else become WORK_READINESS_EXPIRED.
var readinessNotReadyCodes = map[string]bool{
	"POD_OBSERVATION_NOT_READY": true, "WORKER_OBSERVATION_NOT_READY": true, "WORKER_BINDING_MISMATCH": true,
	"WORKER_EXITED": true, "WORKER_ISOLATION_NOT_READY": true, "WORK_READINESS_EXPIRED": true,
	"CONTROL_HEALTH_UNAVAILABLE": true, "HOLD_ACTIVE": true,
}

func readinessExpired(msg string) *Error { return unavailable("WORK_READINESS_EXPIRED", msg) }

var readinessMismatch = fail(http.StatusForbidden, "WORK_READINESS_BINDING_MISMATCH", "work readiness check belongs to another caller or session")

func (h HTTPReadiness) Check(ctx context.Context, c Caller, ref ReadinessRef) error {
	if h.Client == nil || h.BaseURL == "" {
		return ErrUnwired
	}
	if !canonicalUUID(ref.CheckID) || !canonicalUUID(ref.WorkRunID) {
		return readinessExpired("work readiness reference is not a check")
	}
	ctx, cancel := context.WithTimeout(ctx, ReadinessTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		h.BaseURL+"/internal/control-health/work-readiness/checks/"+url.PathEscape(ref.CheckID), nil)
	if err != nil {
		return err
	}
	req.Header.Set(PeerIdentityHeader, c.SAN)
	req.Header.Set("X-Agentarium-Peer-Session", c.SessionID)
	res, err := h.Client.Do(req)
	if err != nil {
		return unavailable("CONTROL_HEALTH_UNAVAILABLE", "work readiness: "+err.Error())
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxReadinessBody+1))
	if err != nil || len(body) > maxReadinessBody {
		return unavailable("CONTROL_HEALTH_UNAVAILABLE", "work readiness: unreadable response")
	}
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return readinessExpired("work readiness check not found")
	case http.StatusForbidden:
		return readinessMismatch
	default:
		return unavailable("CONTROL_HEALTH_UNAVAILABLE", fmt.Sprintf("work readiness: HTTP %d", res.StatusCode))
	}
	var chk readinessCheck
	if err := json.Unmarshal(body, &chk); err != nil {
		return unavailable("CONTROL_HEALTH_UNAVAILABLE", "work readiness: invalid response")
	}
	if chk.CheckID != ref.CheckID || chk.WorkRunID != ref.WorkRunID || chk.SessionID != c.SessionID ||
		chk.WorkloadID != c.WorkloadID || chk.CallerIdentity != c.SAN {
		return readinessMismatch
	}
	if chk.State != "ready" {
		for _, code := range chk.ReasonCodes {
			if code == readinessMismatch.Code {
				return readinessMismatch
			}
			if readinessNotReadyCodes[code] {
				return unavailable(code, "work readiness "+chk.State)
			}
		}
		return readinessExpired("work readiness " + chk.State)
	}
	if chk.RemainingValidMS == nil || *chk.RemainingValidMS <= 0 {
		return readinessExpired("work readiness result expired")
	}
	return nil
}

func canonicalUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

var _ Readiness = HTTPReadiness{}
