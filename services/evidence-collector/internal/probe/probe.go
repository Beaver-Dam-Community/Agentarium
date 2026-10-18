// Package probe is the destination-evidence receipt probe (TASK-08 4 lease
// reporting duty). Every 5 seconds it reads the receipt of a fixed probe action key,
// reports the result as a target-scoped receipt probe to control-health,
// requests a target probe_failed hold after 3 consecutive failures and
// releases that owned hold with 2 consecutive reported passes.
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/receipt"
)

const (
	Interval         = 5 * time.Second
	FailuresForHold  = 3
	PassesForRelease = 2
	Component        = "destination-evidence"
	callTimeout      = 4 * time.Second
	maxBody          = 1 << 20
)

// Reader is internal/receipt.Client.Read.
type Reader interface {
	Read(ctx context.Context, actionID string) (*receipt.Receipt, string, error)
}

// Prober keeps the consecutive counters in memory. Its owned hold is found
// again after a restart with GET /internal/holds?owner_component=.
type Prober struct {
	Receipts       Reader
	ProbeActionKey string
	TargetID       string
	HealthURL      string // https origin of control-health
	Client         *http.Client
	Log            *slog.Logger

	mu       sync.Mutex
	fails    int
	passIDs  []string // probe_result_ids of the current consecutive passes
	holdID   string
	resynced bool
}

// Unhealthy reports 3 or more consecutive probe failures (lease
// observed_state = unhealthy).
func (p *Prober) Unhealthy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fails >= FailuresForHold
}

// HoldID is the open probe_failed hold this prober owns, if known.
func (p *Prober) HoldID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.holdID
}

func (p *Prober) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

// Run probes immediately and then every Interval until ctx ends.
func (p *Prober) Run(ctx context.Context) {
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		if err := p.Once(ctx); err != nil && ctx.Err() == nil {
			p.log().Error("receipt probe step failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Once runs one probe step.
func (p *Prober) Once(ctx context.Context) error {
	if p.Receipts == nil || p.Client == nil || p.ProbeActionKey == "" || p.TargetID == "" || p.HealthURL == "" {
		return errors.New("probe: incomplete configuration")
	}
	if !p.resynced {
		if err := p.resync(ctx); err != nil {
			return err
		}
	}
	rctx, cancel := context.WithTimeout(ctx, callTimeout)
	r, digest, err := p.Receipts.Read(rctx, p.ProbeActionKey)
	cancel()
	pass := err == nil && r.TargetIdentity == p.TargetID
	outcome, refs := "fail", []string{}
	if pass {
		// The pass cites the probe receipt it read (key and JCS digest).
		outcome, refs = "pass", []string{"receipt:" + p.ProbeActionKey + ":" + digest}
	}
	id, rerr := p.report(ctx, outcome, refs)
	p.mu.Lock()
	if pass {
		p.fails = 0
		if rerr == nil {
			p.passIDs = append(p.passIDs, id)
		} else {
			// An unreported pass cannot be cited, so the run restarts.
			p.passIDs = nil
		}
	} else {
		p.fails++
		p.passIDs = nil
	}
	fails, holdID, passIDs := p.fails, p.holdID, append([]string(nil), p.passIDs...)
	p.mu.Unlock()
	if !pass {
		p.log().Warn("receipt probe failed", "target_id", p.TargetID, "consecutive_failures", fails, "err", err)
	}
	if rerr != nil {
		return rerr
	}
	switch {
	case !pass && fails >= FailuresForHold && holdID == "":
		return p.requestHold(ctx)
	case pass && holdID != "" && len(passIDs) >= PassesForRelease:
		return p.release(ctx, holdID, passIDs[len(passIDs)-PassesForRelease:])
	}
	return nil
}

func (p *Prober) report(ctx context.Context, outcome string, refs []string) (string, error) {
	scope := "target"
	body := map[string]any{"probe_kind": "receipt", "scope": scope, "scope_id": p.TargetID, "outcome": outcome, "evidence_refs": refs}
	var ack struct {
		ProbeResultID string `json:"probe_result_id"`
	}
	status, err := p.call(ctx, http.MethodPost, "/internal/control-health/probe-results", body, &ack)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated || ack.ProbeResultID == "" {
		return "", fmt.Errorf("probe: probe result not accepted: HTTP %d", status)
	}
	return ack.ProbeResultID, nil
}

func (p *Prober) requestHold(ctx context.Context) error {
	body := map[string]any{"scope": "target", "scope_id": p.TargetID, "reason": "probe_failed", "evidence_refs": []string{}}
	var ack struct {
		HoldID   *string `json:"hold_id"`
		Decision string  `json:"decision"`
	}
	status, err := p.call(ctx, http.MethodPost, "/internal/holds", body, &ack)
	if err != nil {
		return err
	}
	if (status != http.StatusOK && status != http.StatusCreated) || ack.HoldID == nil || *ack.HoldID == "" {
		return fmt.Errorf("probe: hold not created: HTTP %d decision %q", status, ack.Decision)
	}
	p.mu.Lock()
	p.holdID = *ack.HoldID
	p.mu.Unlock()
	p.log().Warn("target probe_failed hold requested", "target_id", p.TargetID, "hold_id", *ack.HoldID)
	return nil
}

func (p *Prober) release(ctx context.Context, holdID string, passIDs []string) error {
	body := map[string]any{"justification": "receipt probe passed twice in a row", "evidence_refs": []string{}, "probe_result_ids": passIDs}
	var ack struct {
		HoldID string `json:"hold_id"`
	}
	status, err := p.call(ctx, http.MethodPost, "/internal/holds/"+url.PathEscape(holdID)+"/release", body, &ack)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		// Already gone (released elsewhere); stop tracking it.
		status, ack.HoldID = http.StatusOK, holdID
	}
	if status != http.StatusOK || ack.HoldID != holdID {
		return fmt.Errorf("probe: hold release not accepted: HTTP %d", status)
	}
	p.mu.Lock()
	if p.holdID == holdID {
		p.holdID, p.passIDs = "", nil
	}
	p.mu.Unlock()
	p.log().Info("target probe_failed hold released", "target_id", p.TargetID, "hold_id", holdID)
	return nil
}

// resync finds this target's open probe_failed hold owned by
// destination-evidence, so release continues after a restart.
func (p *Prober) resync(ctx context.Context) error {
	var out struct {
		Holds []struct {
			HoldID  string `json:"hold_id"`
			Scope   string `json:"scope"`
			ScopeID string `json:"scope_id"`
			Reason  string `json:"reason"`
		} `json:"holds"`
	}
	status, err := p.call(ctx, http.MethodGet, "/internal/holds?owner_component="+Component, nil, &out)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("probe: owned holds query: HTTP %d", status)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, h := range out.Holds {
		if h.Scope == "target" && h.ScopeID == p.TargetID && h.Reason == "probe_failed" {
			p.holdID = h.HoldID
		}
	}
	p.resynced = true
	return nil
}

func (p *Prober) call(ctx context.Context, method, path string, body any, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(p.HealthURL, "/")+path, rd)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := p.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		return 0, errors.New("probe: invalid control-health response")
	}
	if res.StatusCode/100 == 2 && out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return 0, errors.New("probe: invalid control-health response body")
		}
	}
	return res.StatusCode, nil
}
