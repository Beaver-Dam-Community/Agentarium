package execute

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/redact"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
)

// preClaimReasons are the reason codes a released outcome may carry (COMMON
// failure classification: credential, permit refusal, hold and the checks the claim repeats).
var preClaimReasons = []string{
	"CREDENTIAL_UNAVAILABLE", "PERMIT_INVALID", "HOLD_ACTIVE", "CONTROL_HEALTH_UNAVAILABLE",
	"POLICY_EPOCH_STALE", "CATALOG_DIGEST_MISMATCH", "LOCK_TIMEOUT", "STATE_STORE_UNAVAILABLE",
}

// Config wires an Engine. A nil dependency is Unwired (fail-closed); Adapter
// and Store are required.
type Config struct {
	Adapter     Adapter
	Store       Store
	Inputs      InputStore
	Bundles     BundleSource
	Coordinator Coordinator
	// Credential is the adapter's credential strategy; Kind is required.
	Credential CredentialStrategy
	// Credentials is the broker client (CredentialBroker only).
	Credentials Credentials
	// Refs reads referenced rows for an Adapter that implements Resolver.
	Refs    RefStore
	TLS     TLSMaterial
	Auditor Auditor
	// Transport carries the resolver and dialer; OnWroteHeaders is set by
	// the engine.
	Transport transport.Config
	PodUID    string
	Logger    *slog.Logger
	Now       func() time.Time
	// CallTimeout bounds each internal call (coordinator, broker, audit).
	CallTimeout time.Duration
	// OutcomeRetries and RetryBackoff bound the internal retry of the outcome
	// API. They retry the report, never the external send.
	OutcomeRetries int
	RetryBackoff   time.Duration
	// MaxInFlight bounds concurrently processed executions.
	MaxInFlight int
}

// Engine runs executions for one adapter_id.
type Engine struct {
	cfg  Config
	log  *slog.Logger
	now  func() time.Time
	sem  chan struct{}
	wg   sync.WaitGroup
	base context.Context
}

// Wired reports an error naming every external dependency that is nil, so a
// production binary can refuse to start instead of running with the
// fail-closed Unwired defaults that New fills in.
func (cfg Config) Wired() error {
	var missing []string
	for name, nilDep := range map[string]bool{
		"Inputs": cfg.Inputs == nil, "Bundles": cfg.Bundles == nil, "Coordinator": cfg.Coordinator == nil,
		"Credentials": cfg.Credentials == nil, "TLS": cfg.TLS == nil, "Auditor": cfg.Auditor == nil,
	} {
		if nilDep {
			missing = append(missing, name)
		}
	}
	for _, d := range []any{cfg.Inputs, cfg.Bundles, cfg.Credentials, cfg.TLS, cfg.Auditor} {
		if _, ok := d.(Unwired); ok {
			missing = append(missing, fmt.Sprintf("%T", d))
		}
	}
	if c, ok := cfg.Coordinator.(*HTTPCoordinator); ok && (c == nil || c.Client == nil || c.BaseURL == "") {
		missing = append(missing, "Coordinator client")
	}
	if b, ok := cfg.Credentials.(*HTTPBroker); ok && (b == nil || b.Client == nil || b.BaseURL == "") {
		missing = append(missing, "Credentials client")
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("execute: dependencies not wired: %v", missing)
	}
	return nil
}

// New validates cfg and fills the fail-closed defaults.
func New(cfg Config) (*Engine, error) {
	if cfg.Adapter == nil || cfg.Store == nil {
		return nil, errors.New("execute: Adapter and Store are required")
	}
	// A model turn holds the raw parts; without its own result builder the
	// redacted raw body (thought signatures included) would be result_body.
	if _, w := cfg.Adapter.(ModelTurnWriter); w {
		if _, b := cfg.Adapter.(ResultBuilder); !b {
			return nil, errors.New("execute: an Adapter that writes model turns must implement ResultBuilder")
		}
	}
	// Every post-claim observation carries pod_uid (TASK-03 outcome contract).
	if !ValidUUID(cfg.PodUID) {
		return nil, fmt.Errorf("execute: PodUID %q is not a canonical UUID", cfg.PodUID)
	}
	if cfg.Inputs == nil {
		cfg.Inputs = Unwired{}
	}
	if cfg.Bundles == nil {
		cfg.Bundles = Unwired{}
	}
	switch cfg.Credential.Kind {
	case CredentialNone, CredentialBroker:
	case CredentialTokenFile:
		if cfg.Credential.TokenFile == "" {
			return nil, errors.New("execute: credential strategy token_file needs TokenFile")
		}
	case CredentialTokenSource:
		if cfg.Credential.TokenSource == nil {
			cfg.Credential.TokenSource = Unwired{}
		}
	default:
		return nil, fmt.Errorf("execute: credential strategy %q is not none, broker, token_file or token_source", cfg.Credential.Kind)
	}
	if cfg.Credentials == nil {
		cfg.Credentials = Unwired{}
	}
	if cfg.Refs == nil {
		cfg.Refs = Unwired{}
	}
	if cfg.TLS == nil {
		cfg.TLS = Unwired{}
	}
	if cfg.Auditor == nil {
		cfg.Auditor = Unwired{}
	}
	if cfg.Coordinator == nil {
		cfg.Coordinator = &HTTPCoordinator{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 5 * time.Second
	}
	if cfg.OutcomeRetries <= 0 {
		cfg.OutcomeRetries = 3
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 200 * time.Millisecond
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = 32
	}
	return &Engine{
		cfg:  cfg,
		log:  cfg.Logger.With("adapter_id", cfg.Adapter.ID()),
		now:  cfg.Now,
		sem:  make(chan struct{}, cfg.MaxInFlight),
		base: context.Background(),
	}, nil
}

// Start sets the lifetime of background executions; call it before Submit.
func (e *Engine) Start(ctx context.Context) { e.base = ctx }

// Wait blocks until every background execution has returned.
func (e *Engine) Wait() { e.wg.Wait() }

// Submit is the idempotent execute entry (TASK-05 3.3): it inserts a
// received row and starts the work only when the row is new. A repeated
// decision returns the current row and starts nothing.
func (e *Engine) Submit(ctx context.Context, decisionID, actionID string) (Execution, bool, error) {
	row, created, err := e.cfg.Store.Begin(ctx, decisionID, actionID, e.cfg.Adapter.ID())
	if err != nil {
		return Execution{}, false, err
	}
	if created {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.sem <- struct{}{}
			defer func() { <-e.sem }()
			e.process(e.base, decisionID, actionID)
		}()
	}
	return row, created, nil
}

// Recover is the restart correction (TASK-05 3.3 restart correction), run once at
// start before the server accepts requests: received rows are processed from
// the beginning (no permit was claimed for them by this process); reserved
// rows with a recovery record redo ②–④; reserved rows without one report
// outcome unknown, because a claim may have happened and the response is not
// known. If the attempt was never claimed the coordinator refuses that
// transition and its sweeper releases the expired permit.
func (e *Engine) Recover(ctx context.Context) error {
	rows, err := e.cfg.Store.Unfinished(ctx, e.cfg.Adapter.ID())
	if err != nil {
		return err
	}
	for _, r := range rows {
		switch r.State {
		case StateReceived:
			e.process(ctx, r.DecisionID, r.ActionID)
		case StateReserved:
			e.recoverReserved(ctx, r)
		}
	}
	return nil
}

func (e *Engine) recoverReserved(ctx context.Context, r Execution) {
	p, err := e.cfg.Store.Pending(ctx, r.DecisionID)
	if err == nil {
		e.finishPending(ctx, p)
		return
	}
	if !errors.Is(err, ErrNotFound) {
		e.log.Error("read recovery record", "decision_id", r.DecisionID, "err", err)
		return
	}
	obs := e.baseObservation(r.AttemptID)
	// SPEC-QUESTION: no reason code is defined for "adapter restarted after
	// the reservation", and the coordinator requires at least one for
	// unknown. STATE_STORE_UNAVAILABLE (the adapter lost the attempt's
	// facts) is used; OUTCOME_TIMEOUT belongs to the coordinator sweeper.
	codes := []string{ReasonStateStoreUnavailable}
	p = PendingOutcome{
		DecisionID: r.DecisionID, AttemptID: r.AttemptID, Transition: TransitionUnknown,
		ReasonCodes: codes, Observation: obs,
		Event: &Event{EventID: newUUID(), Type: "attempt_uncertain", ActionID: r.ActionID, AttemptID: r.AttemptID,
			Payload: map[string]any{"attempt_id": r.AttemptID, "stage": "adapter_restart", "reason_codes": codes}},
	}
	if err := e.cfg.Store.SavePending(ctx, p, nil); err != nil {
		e.log.Error("save recovery record", "decision_id", r.DecisionID, "err", err)
		return
	}
	e.finishPending(ctx, p)
}

// baseObservation is the observation of an attempt without a socket: only
// attempt_id and pod_uid (the connection key fields come together or not
// at all).
func (e *Engine) baseObservation(attemptID string) transport.Observation {
	pod := e.cfg.PodUID
	return transport.Observation{AttemptID: attemptID, PodUID: &pod}
}

func (e *Engine) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, e.cfg.CallTimeout)
}

func (e *Engine) emit(ctx context.Context, ev Event) error {
	if ev.EventID == "" {
		ev.EventID = newUUID()
	}
	cctx, cancel := e.call(ctx)
	defer cancel()
	return e.cfg.Auditor.Emit(cctx, ev)
}

func (e *Engine) setState(ctx context.Context, decisionID string, from []string, to, attemptID string) bool {
	ok, err := e.cfg.Store.SetState(ctx, decisionID, from, to, attemptID)
	if err != nil {
		e.log.Error("update adapter_executions", "decision_id", decisionID, "to", to, "err", err)
		return false
	}
	if !ok {
		e.log.Warn("adapter_executions not in the expected state", "decision_id", decisionID, "from", from, "to", to)
	}
	return ok
}

// process runs one received execution up to the end. Failures before the
// reservation that are not a preflight result (bundle not loaded, stored
// values unreadable, audit unavailable) leave the row received: nothing was
// reserved, and the restart correction picks it up again.
func (e *Engine) process(ctx context.Context, decisionID, actionID string) {
	log := e.log.With("decision_id", decisionID, "action_id", actionID)
	bundle, err := e.cfg.Bundles.Current(ctx)
	if err != nil || bundle == nil {
		log.Error("no loaded bundle; execution stays received", "err", err)
		return
	}
	in, err := e.cfg.Inputs.Load(ctx, decisionID, actionID)
	if errors.Is(err, ErrNotFound) {
		e.reject(ctx, log, Inputs{Decision: Decision{DecisionID: decisionID, ActionID: actionID}},
			&Rejection{ReasonCodes: []string{ReasonPreflightMismatch}, ComparedFields: []string{"decision_id"}, Detail: "decision or action not found"})
		return
	}
	if err != nil {
		log.Error("read stored decision/envelope/content; execution stays received", "err", err)
		return
	}
	prep, key, rej, err := e.preflight(ctx, decisionID, actionID, in, bundle)
	if err != nil {
		log.Error("referenced rows unreadable; execution stays received", "err", err)
		return
	}
	if rej != nil {
		e.reject(ctx, log, in, rej)
		return
	}
	// The event_id is stored with the execution row before the event is
	// sent, so a received row processed again after a crash re-sends the
	// same event_id with the same body (TASK-07 deduplicates).
	passedID, err := e.cfg.Store.EventID(ctx, decisionID, "preflight_passed", newUUID())
	if err != nil {
		log.Error("preflight_passed event_id not stored; nothing reserved", "err", err)
		return
	}
	if err := e.emit(ctx, Event{EventID: passedID, Type: "preflight_passed", ActionID: actionID, RequestID: in.Decision.RequestID, Payload: map[string]any{
		"action_id": actionID, "decision_id": decisionID, "wire_body_digest": prep.Plan.WireBodyDigest, "catalog_digest": in.Decision.CatalogDigest,
	}}); err != nil {
		log.Error("preflight_passed not recorded; nothing reserved", "err", err)
		return
	}

	req := ReserveRequest{
		DecisionID: decisionID, ActionID: actionID, RequestID: in.Decision.RequestID,
		ActionDigest: in.Decision.ActionDigest, WireBodyDigest: prep.Plan.WireBodyDigest,
		PolicyEpoch: in.Decision.PolicyEpoch, CatalogDigest: in.Decision.CatalogDigest,
	}
	cctx, cancel := e.call(ctx)
	permit, err := e.cfg.Coordinator.Reserve(cctx, req)
	cancel()
	if err != nil {
		// A refused reservation (epoch, hold, budget, health, expiry) is the
		// coordinator's result and its events; the adapter only ends the
		// execution. An ambiguous error may have left a reservation whose
		// unclaimed permit the sweeper releases.
		if re, ok := definitive(err); ok {
			log.Info("reservation refused", "status", re.Status, "reason_codes", re.ReasonCodes)
		} else {
			log.Error("reservation result unknown; sweeper releases any permit", "err", err)
		}
		e.setState(ctx, decisionID, []string{StateReceived}, StateFailed, "")
		return
	}
	if bad := permitMismatch(permit, req, e.cfg.Adapter.ID()); bad != "" {
		log.Error("permit differs from the reservation request", "field", bad)
		if reUUID.MatchString(permit.AttemptID) {
			e.release(ctx, log, permit.AttemptID, []string{ReasonPermitInvalid})
		}
		e.setState(ctx, decisionID, []string{StateReceived}, StateFailed, "")
		return
	}
	log = log.With("attempt_id", permit.AttemptID)
	if !e.setState(ctx, decisionID, []string{StateReceived}, StateReserved, permit.AttemptID) {
		e.release(ctx, log, permit.AttemptID, []string{ReasonStateStoreUnavailable})
		return
	}
	e.dispatch(ctx, log, in, prep, key, permit)
}

func permitMismatch(p Permit, req ReserveRequest, adapterID string) string {
	switch {
	case p.DecisionID != req.DecisionID:
		return "decision_id"
	case p.ActionID != req.ActionID:
		return "action_id"
	case p.AdapterID != adapterID:
		return "adapter_id"
	case p.ActionDigest != req.ActionDigest:
		return "action_digest"
	case p.WireBodyDigest != req.WireBodyDigest:
		return "wire_body_digest"
	case p.PolicyEpoch != req.PolicyEpoch:
		return "policy_epoch"
	case p.CatalogDigest != req.CatalogDigest:
		return "catalog_digest"
	case !reUUID.MatchString(p.PermitID) || !reUUID.MatchString(p.AttemptID):
		return "permit_id"
	case p.ClaimedAt != nil:
		return "claimed_at"
	}
	return ""
}

func (e *Engine) reject(ctx context.Context, log *slog.Logger, in Inputs, rej *Rejection) {
	log.Info("preflight rejected", "reason_codes", rej.ReasonCodes, "compared_fields", rej.ComparedFields, "detail", rej.Detail)
	// The event is recorded before the state moves: if it cannot be, the row
	// stays received and a restart sends it again with the stored event_id.
	id, err := e.cfg.Store.EventID(ctx, in.Decision.DecisionID, "preflight_rejected", newUUID())
	if err != nil {
		log.Error("preflight_rejected event_id not stored; execution stays received", "err", err)
		return
	}
	if err := e.emit(ctx, Event{EventID: id, Type: "preflight_rejected", ActionID: in.Decision.ActionID, RequestID: in.Decision.RequestID, Payload: map[string]any{
		"action_id": in.Decision.ActionID, "decision_id": in.Decision.DecisionID,
		"reason_codes": rej.ReasonCodes, "compared_fields": rej.ComparedFields,
	}}); err != nil {
		log.Error("preflight_rejected event not recorded; execution stays received", "err", err)
		return
	}
	e.setState(ctx, in.Decision.DecisionID, []string{StateReceived}, StatePreflightRejected, "")
}

// preflight compares the stored decision, envelope and content with each
// other and with the loaded bundle, resolves the referenced rows (Resolver
// adapters only), then runs the adapter's pure mapper (TASK-05 3.3
// preflight). Every disagreement of the stored values is collected. A non-nil
// error is a read failure of the referenced rows: no result, the execution
// stays received.
func (e *Engine) preflight(ctx context.Context, decisionID, actionID string, in Inputs, b *Bundle) (Prepared, DataStateKey, *Rejection, error) {
	d, env := in.Decision, in.Envelope
	rej := &Rejection{}
	add := func(code, field string) {
		if !slices.Contains(rej.ReasonCodes, code) {
			rej.ReasonCodes = append(rej.ReasonCodes, code)
		}
		if !slices.Contains(rej.ComparedFields, field) {
			rej.ComparedFields = append(rej.ComparedFields, field)
		}
	}
	if d.DecisionID != decisionID || d.ActionID != actionID || env.ActionID != actionID {
		add(ReasonPreflightMismatch, "action_id")
	}
	if d.Verdict != "allow" {
		add(ReasonPreflightMismatch, "verdict")
	}
	if d.AdapterID != e.cfg.Adapter.ID() {
		add(ReasonPreflightMismatch, "adapter_id")
	}
	if ad, err := canonical.ActionDigest(env.HashObject()); err != nil || ad != env.ActionDigest || ad != d.ActionDigest {
		add(ReasonPreflightMismatch, "action_digest")
	}
	if d.CatalogDigest != env.CatalogDigest || d.CatalogDigest != b.Catalog.CatalogDigest {
		add(ReasonCatalogDigestMismatch, "catalog_digest")
	}
	if d.PolicyBundleID != b.BundleID {
		add(ReasonPreflightMismatch, "policy_bundle_id")
	}
	if env.ContentDigest != nil {
		if err := canonical.VerifyContent(env, in.Content); err != nil || in.Content.AdapterID != e.cfg.Adapter.ID() {
			add(ReasonContentDigestMismatch, "content_digest")
		}
	}
	var key DataStateKey
	switch env.SessionKind {
	case "user":
		if env.WorkloadID == nil || *env.WorkloadID == "" {
			add(ReasonPreflightMismatch, "workload_id")
		} else {
			key.WorkloadID = *env.WorkloadID
		}
	case "service":
		if env.WorkloadID != nil || !reUUID.MatchString(env.SessionID) {
			add(ReasonPreflightMismatch, "session_id")
		} else if d.ServiceSessionID == "" || d.ServiceSessionID != env.SessionID {
			// session_id is not an action_digest input, so the stored decision's
			// service_session_id is what binds the action to its service
			// session (and the evidence-reader header to the decision).
			add(ReasonPreflightMismatch, "service_session_id")
		} else {
			key.ServiceSessionID = env.SessionID
		}
	default:
		add(ReasonPreflightMismatch, "session_kind")
	}
	if len(rej.ReasonCodes) > 0 {
		return Prepared{}, key, rej, nil
	}
	in.Resolved = nil
	if r, ok := e.cfg.Adapter.(Resolver); ok {
		resolved, rrej, err := e.resolve(ctx, r, in, b)
		if err != nil || rrej != nil {
			return Prepared{}, key, rrej, err
		}
		in.Resolved = resolved
	}
	prep, prej := e.cfg.Adapter.Prepare(in, b)
	if prej != nil {
		return Prepared{}, key, prej, nil
	}
	if prep.ResponseDataClass == "inherit" {
		prep.ResponseDataClass = env.DataClass
	}
	// The adapter's credential strategy must agree with the catalog: only a
	// broker adapter has a credential_binding.
	if (e.cfg.Credential.Kind == CredentialBroker) != (prep.CredentialBinding != "") {
		return Prepared{}, key, &Rejection{ReasonCodes: []string{ReasonPreflightMismatch}, ComparedFields: []string{"credential_binding"},
			Detail: fmt.Sprintf("credential strategy %s with credential_binding %q", e.cfg.Credential.Kind, prep.CredentialBinding)}, nil
	}
	// The request must also fit the transport rules with an attempt header
	// bound, including the TLS selection (ca_ref and expected URI SAN); a
	// credential header is checked again after the credential is obtained.
	if err := transport.Validate(transport.Request{Plan: prep.Plan, AttemptID: "00000000-0000-0000-0000-000000000000", CARef: prep.CARef}); err != nil {
		return Prepared{}, key, &Rejection{ReasonCodes: []string{ReasonPreflightMismatch}, ComparedFields: []string{"wire_plan"}, Detail: err.Error()}, nil
	}
	return prep, key, nil, nil
}

// release reports a pre-claim failure (attempt released, budget restored)
// and ends the execution. If the report cannot be delivered the sweeper
// releases the permit after it expires.
func (e *Engine) release(ctx context.Context, log *slog.Logger, attemptID string, codes []string) {
	if err := e.outcome(ctx, attemptID, OutcomeRequest{Transition: TransitionReleased, ReasonCodes: codes}); err != nil {
		log.Error("released outcome not delivered; sweeper releases on permit expiry", "err", err)
	}
}

// outcome posts a transition with the internal retry for ambiguous errors.
func (e *Engine) outcome(ctx context.Context, attemptID string, req OutcomeRequest) error {
	if req.ReasonCodes == nil {
		req.ReasonCodes = []string{}
	}
	var err error
	for i := 0; i < e.cfg.OutcomeRetries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(e.cfg.RetryBackoff << (i - 1)):
			}
		}
		cctx, cancel := e.call(ctx)
		err = e.cfg.Coordinator.Outcome(cctx, attemptID, req)
		cancel()
		if err == nil {
			return nil
		}
		if _, ok := definitive(err); ok {
			return err
		}
	}
	return err
}

func releaseCodes(err error) []string {
	if re, ok := definitive(err); ok {
		var out []string
		for _, c := range re.ReasonCodes {
			if slices.Contains(preClaimReasons, c) && !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{ReasonPermitInvalid}
}

// dispatch is the part after the reservation COMMIT: credential, claim, one
// attempt, the outcome and the commit order.
func (e *Engine) dispatch(ctx context.Context, log *slog.Logger, in Inputs, prep Prepared, key DataStateKey, permit Permit) {
	decisionID, attemptID := in.Decision.DecisionID, permit.AttemptID
	fail := func(codes []string) {
		e.release(ctx, log, attemptID, codes)
		e.setState(ctx, decisionID, []string{StateReserved}, StateFailed, "")
	}

	treq := transport.Request{Plan: prep.Plan, AttemptID: attemptID, PodUID: e.cfg.PodUID}
	cert, err := e.cfg.TLS.ClientCertificate()
	if err != nil || cert == nil {
		log.Error("client certificate unavailable", "err", err)
		fail([]string{ReasonCredentialUnavailable})
		return
	}
	treq.ClientCert = cert
	roots, err := e.cfg.TLS.RootCAs(prep.CARef)
	if err != nil {
		log.Error("ca_ref pool unavailable", "ca_ref", prep.CARef, "err", err)
		fail([]string{ReasonCredentialUnavailable})
		return
	}
	treq.RootCAs = roots
	treq.CARef = prep.CARef
	if prep.CARef != "system" && roots == nil {
		log.Error("ca_ref pool missing", "ca_ref", prep.CARef)
		fail([]string{ReasonCredentialUnavailable})
		return
	}
	cred, err := e.credential(ctx, attemptID, prep.CredentialBinding)
	// #225: an adapter whose target takes one credential form checks it here.
	if cc, ok := e.cfg.Adapter.(CredentialChecker); ok && err == nil && prep.CredentialBinding != "" {
		err = cc.CheckCredential(prep.CredentialBinding, cred)
	}
	if err != nil {
		log.Error("credential unavailable", "strategy", e.cfg.Credential.Kind, "binding", prep.CredentialBinding, "err", err)
		fail([]string{ReasonCredentialUnavailable})
		return
	}
	if cred.HeaderName != "" {
		treq.CredentialHeader, treq.CredentialHeaderValue = cred.HeaderName, cred.HeaderValue
	}
	if cred.SecretVersion != "" {
		log = log.With("secret_version", cred.SecretVersion)
	}
	if err := transport.Validate(treq); err != nil {
		log.Error("request with credential does not fit the transport rules", "err", err)
		fail([]string{ReasonCredentialUnavailable})
		return
	}

	// Claim. The permit check repeats the decision, hold and health checks;
	// only execution_allowed=true from the first claim permits the send.
	cctx, cancel := e.call(ctx)
	res, err := e.cfg.Coordinator.Check(cctx, permit.PermitID, CheckRequest{
		AttemptID: attemptID, ActionDigest: in.Decision.ActionDigest,
		PolicyEpoch: in.Decision.PolicyEpoch, WireBodyDigest: prep.Plan.WireBodyDigest,
	})
	cancel()
	if err != nil {
		if _, ok := definitive(err); ok {
			log.Info("permit refused", "err", err)
			fail(releaseCodes(err))
			return
		}
		// The claim may have committed. A release is refused for a claimed
		// permit; then nothing was sent, which is a failure after the claim.
		log.Error("permit claim result unknown", "err", err)
		rerr := e.outcome(ctx, attemptID, OutcomeRequest{Transition: TransitionReleased, ReasonCodes: []string{ReasonPermitInvalid}})
		if _, refused := definitive(rerr); refused {
			e.endWithoutSend(ctx, log, in, attemptID, []string{ReasonPermitInvalid})
			return
		}
		if rerr != nil {
			log.Error("released outcome not delivered", "err", rerr)
		}
		e.setState(ctx, decisionID, []string{StateReserved}, StateFailed, "")
		return
	}
	if !res.ExecutionAllowed {
		fail([]string{ReasonPermitInvalid})
		return
	}
	// Last comparison before the socket: the body and its length are what the
	// permit was issued for.
	if canonical.WireBodyDigest(treq.Plan.BodyBytes) != permit.WireBodyDigest || len(treq.Plan.BodyBytes) != len(prep.Plan.BodyBytes) {
		e.endWithoutSend(ctx, log, in, attemptID, []string{ReasonPreflightMismatch})
		return
	}
	if e.cfg.Credential.Kind != CredentialNone && !cred.ExpiresAt.After(e.now()) {
		e.endWithoutSend(ctx, log, in, attemptID, []string{ReasonCredentialUnavailable})
		return
	}

	// Send. WroteHeaders starts the dispatched report in its own goroutine so
	// the write is not delayed; the final report waits for it to keep order.
	var dispatched sync.WaitGroup
	tcfg := e.cfg.Transport
	tcfg.Now = e.now
	tcfg.OnWroteHeaders = func(obs transport.Observation) {
		dispatched.Add(1)
		go func() {
			defer dispatched.Done()
			if err := e.outcome(ctx, attemptID, OutcomeRequest{Transition: TransitionDispatched, Observation: &obs}); err != nil {
				log.Error("dispatched outcome not delivered", "err", err)
			}
			payload := map[string]any{"attempt_id": attemptID, "peer_addr": obs.PeerAddr, "peer_port": obs.PeerPort, "send_started_at": obs.SendStartedAt}
			if err := e.emit(ctx, Event{Type: "dispatch_started", ActionID: in.Decision.ActionID, RequestID: in.Decision.RequestID, AttemptID: attemptID, Payload: payload}); err != nil {
				log.Error("dispatch_started event not recorded", "err", err)
			}
		}()
	}
	r := transport.Do(ctx, tcfg, treq)
	dispatched.Wait()

	var raise *DataStateRaise
	var fallback ActionResult
	var m Mapping
	if r.Responded {
		m = e.mapResponse(in, prep, r)
		// provider_request_id goes into the observation before the recovery
		// record and the response_received event are made from it.
		if m.ProviderRequestID != "" {
			if validProviderRequestID(m.ProviderRequestID) {
				id := m.ProviderRequestID
				r.Observation.ProviderRequestID = &id
			} else {
				log.Warn("provider request id not recorded: longer than 256 bytes or not printable ASCII", "bytes", len(m.ProviderRequestID))
			}
		}
	}
	p := PendingOutcome{DecisionID: decisionID, AttemptID: attemptID, Observation: r.Observation}
	switch {
	case r.Responded:
		p.Transition, p.ReasonCodes = TransitionResponseReceived, m.ReasonCodes
		p.Event = &Event{EventID: newUUID(), Type: "response_received", ActionID: in.Decision.ActionID, RequestID: in.Decision.RequestID, AttemptID: attemptID, Payload: map[string]any{
			"attempt_id": attemptID, "status_code": r.StatusCode, "provider_request_id": r.Observation.ProviderRequestID,
			"k8s_audit_id": r.Observation.K8sAuditID, "response_at": r.Observation.ResponseAt,
		}}
		fallback = e.conservativeResult(in, prep, m, attemptID)
		e.attachResult(log, &p, in, prep, r, m, fallback)
		raise = &DataStateRaise{Key: key, DataClass: prep.ResponseDataClass, Source: in.Envelope.CanonicalTarget.TargetID, AttemptID: attemptID}
	case r.Unknown():
		p.Transition, p.ReasonCodes = TransitionUnknown, r.ReasonCodes
		p.Event = &Event{EventID: newUUID(), Type: "attempt_uncertain", ActionID: in.Decision.ActionID, RequestID: in.Decision.RequestID, AttemptID: attemptID,
			Payload: map[string]any{"attempt_id": attemptID, "stage": r.Stage, "reason_codes": r.ReasonCodes}}
		log.Warn("no response after WroteHeaders; outcome unknown, no retry", "err", r.Err)
	default:
		p.Transition, p.ReasonCodes = TransitionFailed, r.ReasonCodes
		p.Event = &Event{EventID: newUUID(), Type: "attempt_failed", ActionID: in.Decision.ActionID, RequestID: in.Decision.RequestID, AttemptID: attemptID,
			Payload: map[string]any{"attempt_id": attemptID, "stage": failedStage(r.Stage), "reason_codes": r.ReasonCodes}}
		log.Warn("attempt failed before WroteHeaders", "stage", r.Stage, "reason_codes", r.ReasonCodes, "err", r.Err)
	}
	if p.ReasonCodes == nil {
		p.ReasonCodes = []string{}
	}
	// ① (and the recovery record) in one transaction. Without it ② must not
	// run: the coordinator sweeper turns the claimed attempt into unknown.
	err = e.cfg.Store.SavePending(ctx, p, raise)
	var aux *AuxWriteError
	if errors.As(err, &aux) && p.BuildResult != nil {
		// The model turn or the result built from it failed and nothing was
		// written: the response is still recorded, without the turn and with
		// the conservative result.
		log.Error("model turn or its result not stored; saving the conservative result without it", "err", err)
		p.ModelTurn, p.BuildResult, p.Result = nil, nil, &fallback
		err = e.cfg.Store.SavePending(ctx, p, raise)
	}
	if err != nil {
		log.Error("workload_data_state/recovery record not stored; outcome left to the sweeper", "err", err)
		return
	}
	if p.BuildResult != nil {
		// The stored record holds the result built in the transaction (or the
		// first record of the decision); ②–④ continue from it.
		stored, err := e.cfg.Store.Pending(ctx, decisionID)
		if err != nil {
			log.Error("recovery record not readable after saving; execution stays reserved for the next restart", "err", err)
			return
		}
		p = stored
	}
	e.finishPending(ctx, p)
}

// mapResponse is the adapter's mapping of a received response: the
// ContextMapper when the adapter has one, MapResponse otherwise.
func (e *Engine) mapResponse(in Inputs, prep Prepared, r transport.Result) Mapping {
	if cm, ok := e.cfg.Adapter.(ContextMapper); ok {
		return cm.MapResponseWithContext(in, prep, r)
	}
	return e.cfg.Adapter.MapResponse(r)
}

func validProviderRequestID(s string) bool {
	if len(s) > MaxProviderRequestID {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// attachResult sets the result of a received response on p. With a model
// turn the result is built inside the SavePending transaction from the
// allocated key (p.BuildResult); otherwise it is built here. A turn or a
// result the adapter cannot build yields fallback, without the turn.
func (e *Engine) attachResult(log *slog.Logger, p *PendingOutcome, in Inputs, prep Prepared, r transport.Result, m Mapping, fallback ActionResult) {
	turn, err := e.modelTurn(in, prep, r, m)
	if err != nil {
		log.Error("model turn not built; storing the conservative result without it", "err", err)
		p.Result = &fallback
		return
	}
	attemptID := p.AttemptID
	if turn != nil {
		p.ModelTurn = turn
		p.BuildResult = func(aux AuxWriteResult) (ActionResult, error) {
			return e.buildResult(in, prep, r, m, attemptID, &aux)
		}
		return
	}
	res, err := e.buildResult(in, prep, r, m, attemptID, nil)
	if err != nil {
		log.Error("build action result", "err", err)
		if _, ok := e.cfg.Adapter.(ResultBuilder); ok {
			res = fallback
		}
	}
	p.Result = &res
}

// modelTurn asks a ModelTurnWriter adapter for the model_turns row of the
// response and checks it. Errors never quote the raw parts.
func (e *Engine) modelTurn(in Inputs, prep Prepared, r transport.Result, m Mapping) (*ModelTurnWrite, error) {
	w, ok := e.cfg.Adapter.(ModelTurnWriter)
	if !ok {
		return nil, nil
	}
	t, err := w.ModelTurn(in, prep, r, m)
	if err != nil || t == nil {
		return nil, err
	}
	tw := *t
	if tw.ActionID == "" {
		tw.ActionID = in.Decision.ActionID
	}
	if tw.SessionKey == "" {
		tw.SessionKey = in.Envelope.SessionID
	}
	raw := bytes.TrimSpace(tw.RawParts)
	switch {
	case tw.ActionID != in.Decision.ActionID:
		return nil, errors.New("execute: model turn action_id differs from the decision")
	case tw.SessionKey != in.Envelope.SessionID || !ValidUUID(tw.SessionKey):
		return nil, errors.New("execute: model turn session_key differs from the envelope session")
	case !ValidUUID(tw.ConversationID):
		return nil, errors.New("execute: model turn conversation_id is not a canonical UUID")
	case tw.ExpiresAt.IsZero():
		return nil, errors.New("execute: model turn has no expires_at")
	case len(raw) == 0 || raw[0] != '[' || canonical.CheckStrictJSON(raw) != nil:
		return nil, errors.New("execute: model turn raw_parts is not a strict JSON array")
	}
	tw.RawParts = json.RawMessage(raw)
	return &tw, nil
}

// endWithoutSend ends a claimed attempt that sent nothing: outcome failed.
func (e *Engine) endWithoutSend(ctx context.Context, log *slog.Logger, in Inputs, attemptID string, codes []string) {
	p := PendingOutcome{
		DecisionID: in.Decision.DecisionID, AttemptID: attemptID, Transition: TransitionFailed, ReasonCodes: codes,
		Observation: e.baseObservation(attemptID),
		Event: &Event{EventID: newUUID(), Type: "attempt_failed", ActionID: in.Decision.ActionID, RequestID: in.Decision.RequestID, AttemptID: attemptID,
			Payload: map[string]any{"attempt_id": attemptID, "stage": transport.StageWriteHeaders, "reason_codes": codes}},
	}
	if err := e.cfg.Store.SavePending(ctx, p, nil); err != nil {
		log.Error("recovery record not stored; outcome left to the sweeper", "err", err)
		return
	}
	e.finishPending(ctx, p)
}

// failedStage maps a transport stage to attempt_failed.stage
// (connect/tls/write_headers).
func failedStage(s string) string {
	switch s {
	case transport.StageTLS:
		return transport.StageTLS
	case transport.StageWriteHeaders:
		return transport.StageWriteHeaders
	default:
		return transport.StageConnect
	}
}

// finishPending is ② outcome → event → ③ action_results → ④ final state,
// redone from the recovery record on restart. The event keeps the event_id
// stored in the record.
func (e *Engine) finishPending(ctx context.Context, p PendingOutcome) {
	log := e.log.With("decision_id", p.DecisionID, "attempt_id", p.AttemptID)
	obs := p.Observation
	// Only a 2xx continues. A refusal (4xx) or an undelivered report leaves
	// the execution reserved with its recovery record: ③ and ④ are not done
	// for an attempt whose outcome the coordinator has not recorded, and the
	// next restart reports the same outcome again (the coordinator answers
	// an identical re-report with 2xx).
	if err := e.outcome(ctx, p.AttemptID, OutcomeRequest{Transition: p.Transition, Observation: &obs, ReasonCodes: p.ReasonCodes}); err != nil {
		log.Error("outcome not recorded by the coordinator; execution stays reserved for the next restart", "transition", p.Transition, "err", err)
		return
	}
	// The attempt event must be recorded before ③ and ④; otherwise the row
	// stays reserved and a restart re-sends it with the stored event_id.
	if p.Event != nil {
		if err := e.emit(ctx, *p.Event); err != nil {
			log.Error("attempt event not recorded; execution stays reserved for the next restart", "type", p.Event.Type, "err", err)
			return
		}
	}
	final := StateFailed
	if p.Result != nil {
		if err := e.cfg.Store.InsertResult(ctx, *p.Result); err != nil {
			log.Error("action_results not stored; will be redone on restart", "err", err)
			return
		}
		final = StateCompleted
	}
	e.setState(ctx, p.DecisionID, []string{StateReserved}, final, "")
}

// buildResult makes the ActionResult of a received response. For a
// ResultBuilder adapter the body is the one it returns (aux is its write in
// the recovery transaction); an error means the result must not be used.
// Otherwise it is the bounded body, redacted with the catalog redact_fields,
// when it is a strict JSON object or array, with the mapping's truncated and
// truncation_reason. An oversize, empty, non-JSON or scalar body is not kept
// (result_body null).
//
// SPEC-QUESTION: COMMON does not define result_digest. It is the canonical
// digest (JCS SHA-256) of the stored result_body, and SHA-256("null") when
// nothing is kept (JCS here accepts only objects and arrays).
func (e *Engine) buildResult(in Inputs, prep Prepared, r transport.Result, m Mapping, attemptID string, aux *AuxWriteResult) (ActionResult, error) {
	res := ActionResult{
		ActionID: in.Decision.ActionID, AttemptID: attemptID, ExecutionState: m.ExecutionState,
		DataClass: prep.ResponseDataClass, ResultBody: json.RawMessage("null"),
		EvidenceLevel: m.EvidenceLevel, CreatedAt: e.now().UTC(),
	}
	res.ResultDigest = canonical.SHA256Hex(res.ResultBody)
	if b, ok := e.cfg.Adapter.(ResultBuilder); ok {
		body, truncated, reason, err := b.BuildResult(in, prep, r, m, aux)
		if err != nil {
			return ActionResult{}, err
		}
		if err := setBody(&res, body, truncated, reason); err != nil {
			return ActionResult{}, err
		}
		return res, nil
	}
	// The mapping's truncation (kubernetes-reader continue). An invalid pair
	// is a mapping error: the conservative result, not a guess.
	var reason *string
	if m.TruncationReason != "" {
		reason = &m.TruncationReason
	}
	if m.Truncated != (reason != nil) {
		return e.conservativeResult(in, prep, m, attemptID), errors.New("execute: mapping truncation_reason must be set exactly when truncated")
	}
	res.Truncated, res.TruncationReason = m.Truncated, reason
	body := bytes.TrimSpace(r.Body)
	if r.Oversize || len(body) == 0 || (body[0] != '{' && body[0] != '[') || canonical.CheckStrictJSON(body) != nil {
		return res, nil
	}
	red, err := redact.JSON(body, prep.RedactFields)
	if err != nil {
		return res, err
	}
	d, err := canonical.CanonicalDigestJSON(red)
	if err != nil {
		return res, err
	}
	res.ResultBody, res.ResultDigest = json.RawMessage(red), d
	return res, nil
}

// setBody stores an adapter-built result body after checking it against the
// action_results columns.
func setBody(res *ActionResult, body json.RawMessage, truncated bool, reason *string) error {
	if truncated != (reason != nil) {
		return errors.New("execute: truncation_reason must be set exactly when truncated")
	}
	if reason != nil && *reason == "" {
		return errors.New("execute: empty truncation_reason")
	}
	res.Truncated, res.TruncationReason = truncated, reason
	b := bytes.TrimSpace(body)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if (b[0] != '{' && b[0] != '[') || canonical.CheckStrictJSON(b) != nil {
		return errors.New("execute: adapter result body is not JSON null or a strict JSON object or array")
	}
	d, err := canonical.CanonicalDigestJSON(b)
	if err != nil {
		return err
	}
	res.ResultBody, res.ResultDigest = json.RawMessage(b), d
	return nil
}

// conservativeResult is the result of a received response whose result the
// adapter could not build (ResultBuilder error or invalid body, invalid or
// unstorable model turn): result_body null, an accepted execution_state
// lowered to failed, evidence_level as mapped (the target did receive the
// request). The outcome keeps the mapped reason codes and the model turn is
// not written, so nothing can reference it.
//
// SPEC-QUESTION: COMMON has no reason code for "the adapter could not build
// the result of a received response"; the mapped reason codes are reported
// unchanged and only action_results shows the failure.
func (e *Engine) conservativeResult(in Inputs, prep Prepared, m Mapping, attemptID string) ActionResult {
	state := m.ExecutionState
	if state == "accepted" || state == "effect_verified" {
		state = "failed"
	}
	return ActionResult{
		ActionID: in.Decision.ActionID, AttemptID: attemptID, ExecutionState: state,
		DataClass: prep.ResponseDataClass, ResultBody: json.RawMessage("null"),
		ResultDigest: canonical.SHA256Hex([]byte("null")), EvidenceLevel: m.EvidenceLevel, CreatedAt: e.now().UTC(),
	}
}

// ValidUUID reports the lowercase UUID form used for every server ID.
func ValidUUID(s string) bool { return reUUID.MatchString(s) }

// newUUID returns a random (version 4) UUID in canonical lowercase form.
func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
