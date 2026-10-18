package store

// TASK-10 3.5a/3.5b work-readiness: session worker registration, the node
// witness that makes a binding observed, work-readiness checks and their
// node challenge (COMMON agent work start contract, session-dedicated worker contract).
//
// Readiness is never granted from caller input: the instance binding comes
// from correlation.lifecycle_intervals for the Pod UID of the runtime's
// certificate, the root exec from a committed audit.kernel_events row
// matched by audit.worker_exec_evidence, and liveness/filter state from a
// node-sensors answer to a server nonce on the caller's own node and boot.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/store/healthdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

var _ health.WorkerBackend = (*Store)(nil)

func coded(status int, code string) error { return health.Coded(status, code) }

var (
	errNotReadyPod    = coded(http.StatusServiceUnavailable, health.CodePodNotReady)
	errNotReadyWorker = coded(http.StatusServiceUnavailable, health.CodeWorkerNotReady)
	errWorkerExited   = coded(http.StatusServiceUnavailable, health.CodeWorkerExited)
	errUnavailable    = coded(http.StatusServiceUnavailable, health.CodeHealthUnavailable)
)

// runtimeCaller is the runtime the gateway forwarded, resolved from its
// unrevoked TASK-03 certificate (pod/node/boot) and registered runtime role.
type runtimeCaller struct {
	SAN, WorkloadID, PodUID, NodeUID, BootID string
}

type sessionRow struct {
	Tenant string
}

type bindingRow struct {
	ID, InstanceID, SessionID, WorkloadID, Caller, Epoch string
	SupervisorHint, WorkerHint                           health.ProcessHint
	IsolationDigest, RegistrationDigest                  string
	Instance                                             *health.InstanceBinding
	RootExecID                                           *string
	ExecEventRef, NodeEvidenceRef                        *string
	SensorGeneration                                     *int64
	State                                                string
	RegisteredAt                                         time.Time
	ObservedAt, EndedAt                                  *time.Time
	ReasonCodes                                          []string
	AuditEventRef                                        string
}

const bindingColumns = `worker_binding_id::text, worker_instance_id::text, session_id::text, workload_id, caller_identity,
 runtime_process_epoch::text, supervisor_process_hint, worker_process_hint, isolation_profile_digest, registration_digest,
 instance_binding, root_exec_id, exec_event_ref::text, node_evidence_ref::text, sensor_generation, state, registered_at,
 observed_at, ended_at, reason_codes, audit_event_ref::text`

func scanBinding(row pgx.Row) (bindingRow, error) {
	var b bindingRow
	var sup, wrk, inst []byte
	err := row.Scan(&b.ID, &b.InstanceID, &b.SessionID, &b.WorkloadID, &b.Caller, &b.Epoch, &sup, &wrk, &b.IsolationDigest,
		&b.RegistrationDigest, &inst, &b.RootExecID, &b.ExecEventRef, &b.NodeEvidenceRef, &b.SensorGeneration, &b.State,
		&b.RegisteredAt, &b.ObservedAt, &b.EndedAt, &b.ReasonCodes, &b.AuditEventRef)
	if err != nil {
		return b, err
	}
	if json.Unmarshal(sup, &b.SupervisorHint) != nil || json.Unmarshal(wrk, &b.WorkerHint) != nil {
		return b, errors.New("stored process hint unreadable")
	}
	if inst != nil {
		b.Instance = &health.InstanceBinding{}
		if json.Unmarshal(inst, b.Instance) != nil {
			return b, errors.New("stored instance binding unreadable")
		}
	}
	return b, nil
}

func (b bindingRow) public() health.WorkerBinding {
	refs := []string{}
	if b.NodeEvidenceRef != nil {
		refs = append(refs, "worker_evidence:"+*b.NodeEvidenceRef)
	}
	if b.ExecEventRef != nil {
		refs = append(refs, "kernel_event:"+*b.ExecEventRef)
	}
	codes := b.ReasonCodes
	if codes == nil {
		codes = []string{}
	}
	return health.WorkerBinding{WorkerBindingID: b.ID, WorkerInstanceID: b.InstanceID, SessionID: b.SessionID, WorkloadID: b.WorkloadID,
		CallerIdentity: b.Caller, RuntimeProcessEpoch: b.Epoch, InstanceBinding: b.Instance, RootExecID: b.RootExecID,
		SensorGeneration: b.SensorGeneration, State: b.State, RegisteredAt: b.RegisteredAt, ObservedAt: b.ObservedAt,
		EndedAt: b.EndedAt, ReasonCodes: codes, EvidenceRefs: refs, AuditEventRef: b.AuditEventRef}
}

func selectBinding(ctx context.Context, tx pgx.Tx, id, lock string) (bindingRow, error) {
	b, err := scanBinding(tx.QueryRow(ctx, `SELECT `+bindingColumns+` FROM health.session_process_bindings WHERE worker_binding_id=$1 `+lock, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return b, health.ErrNotFound
	}
	return b, err
}

type checkRow struct {
	health.ReadinessCheck
	Deadline time.Time
}

const checkColumns = `c.check_id::text, c.work_run_id::text, c.checkpoint, c.session_id::text, c.workload_id, c.caller_identity,
 c.runtime_process_epoch::text, c.worker_instance_id::text, c.worker_binding_id::text, c.root_exec_id, c.worker_evidence_refs,
 c.instance_binding, c.sensor_generation, c.rule_hash, c.policy_epoch, c.challenge_id::text, c.challenge_evidence_refs, c.state,
 c.reason_codes, c.created_at, c.checked_at, c.expires_at, c.audit_event_ref::text, g.deadline`

func selectCheck(ctx context.Context, tx pgx.Tx, id, lock string) (checkRow, error) {
	var c checkRow
	var wrefs, crefs, inst []byte
	err := tx.QueryRow(ctx, `SELECT `+checkColumns+` FROM health.work_readiness_checks c
JOIN health.worker_challenges g ON g.check_id=c.check_id WHERE c.check_id=$1 `+lock, id).Scan(
		&c.CheckID, &c.WorkRunID, &c.Checkpoint, &c.SessionID, &c.WorkloadID, &c.CallerIdentity, &c.RuntimeProcessEpoch,
		&c.WorkerInstanceID, &c.WorkerBindingID, &c.RootExecID, &wrefs, &inst, &c.SensorGeneration, &c.RuleHash, &c.PolicyEpoch,
		&c.ChallengeID, &crefs, &c.State, &c.ReasonCodes, &c.CreatedAt, &c.CheckedAt, &c.ExpiresAt, &c.AuditEventRef, &c.Deadline)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, health.ErrNotFound
	}
	if err != nil {
		return c, err
	}
	if json.Unmarshal(wrefs, &c.WorkerEvidenceRefs) != nil || json.Unmarshal(crefs, &c.ChallengeEvidenceRefs) != nil {
		return c, errors.New("stored evidence refs unreadable")
	}
	if inst != nil {
		c.InstanceBinding = &health.InstanceBinding{}
		if json.Unmarshal(inst, c.InstanceBinding) != nil {
			return c, errors.New("stored instance binding unreadable")
		}
	}
	if c.ReasonCodes == nil {
		c.ReasonCodes = []string{}
	}
	return c, nil
}

func (s *Store) beginWrite(ctx context.Context) (pgx.Tx, *healthdb.Queries, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, nil, err
	}
	return tx, healthdb.New(tx), nil
}

// requireGateway admits only a registered gateway principal with a current
// certificate: the only caller allowed to forward a runtime identity
// (COMMON internal API table "gateway relay only").
func requireGateway(ctx context.Context, q *healthdb.Queries, peer health.Peer) error {
	if _, err := q.Certificate(ctx, healthdb.CertificateParams{Serial: peer.Serial, San: peer.SAN}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return health.ErrForbidden
		}
		return err
	}
	principal, err := q.Principal(ctx, peer.SAN)
	if errors.Is(err, pgx.ErrNoRows) {
		return health.ErrForbidden
	}
	if err != nil {
		return err
	}
	if principal.Component != "gateway" {
		return health.ErrForbidden
	}
	return nil
}

// requireSensor admits a registered node-sensors principal on its own,
// current node boot and returns that boot.
func requireSensor(ctx context.Context, q *healthdb.Queries, peer health.Peer) (healthdb.HealthNodeBootGeneration, error) {
	var none healthdb.HealthNodeBootGeneration
	cert, err := q.Certificate(ctx, healthdb.CertificateParams{Serial: peer.Serial, San: peer.SAN})
	if errors.Is(err, pgx.ErrNoRows) {
		return none, health.ErrForbidden
	}
	if err != nil {
		return none, err
	}
	principal, err := q.Principal(ctx, peer.SAN)
	if errors.Is(err, pgx.ErrNoRows) {
		return none, health.ErrForbidden
	}
	if err != nil {
		return none, err
	}
	if principal.Component != "node-sensors" || !cert.NodeUid.Valid || !cert.BootID.Valid {
		return none, health.ErrForbidden
	}
	current, err := currentNode(ctx, q, cert.NodeUid)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, pgx.ErrTooManyRows) {
		return none, health.ErrForbidden
	}
	if err != nil {
		return none, err
	}
	if current.BootID != cert.BootID.String {
		return none, health.ErrForbidden
	}
	return current, nil
}

func lookupRuntime(ctx context.Context, tx pgx.Tx, san string) (runtimeCaller, error) {
	ns, ksa, pod, ok := health.RuntimeSAN(san)
	if !ok {
		return runtimeCaller{}, health.ErrInvalid
	}
	rc := runtimeCaller{SAN: san, WorkloadID: ns + "/" + ksa, PodUID: pod}
	var podUID, node, boot *string
	err := tx.QueryRow(ctx, `SELECT c.pod_uid::text, c.node_uid::text, c.boot_id FROM identity.issued_certificates c
JOIN identity.registered_workloads w ON w.namespace=c.namespace AND w.ksa=c.ksa
WHERE c.san_uri=$1 AND c.namespace=$2 AND c.ksa=$3 AND w.role='runtime' AND w.enabled AND c.revoked_at IS NULL
  AND c.issued_at<=statement_timestamp() AND c.expires_at>statement_timestamp()
ORDER BY c.issued_at DESC, c.serial LIMIT 1`, san, ns, ksa).Scan(&podUID, &node, &boot)
	if errors.Is(err, pgx.ErrNoRows) {
		return rc, coded(http.StatusForbidden, health.CodeSessionBinding)
	}
	if err != nil {
		return rc, err
	}
	if podUID == nil || *podUID != pod {
		return rc, coded(http.StatusForbidden, health.CodeSessionBinding)
	}
	if node == nil || boot == nil || *boot == "" {
		return rc, errNotReadyPod
	}
	rc.NodeUID, rc.BootID = *node, *boot
	return rc, nil
}

// lookupSession reads identity.work_readiness_session_view (TASK-03, SELECT
// only). The session must be claimed by exactly this runtime SAN, live and
// of its workload.
// SPEC-QUESTION: budget_available is not a readiness condition here; a
// session without standing rules has no budget rows and would never be
// ready. Action budgets stay enforced at reservation.
func lookupSession(ctx context.Context, tx pgx.Tx, id string, rc runtimeCaller, mismatch string) (sessionRow, error) {
	var row sessionRow
	var workload, state string
	var live, budget bool
	var claimed *string
	err := tx.QueryRow(ctx, `SELECT tenant, workload_id, state, expires_at>statement_timestamp(), claimed_workload_identity, budget_available
FROM identity.work_readiness_session_view WHERE session_id=$1`, id).Scan(&row.Tenant, &workload, &state, &live, &claimed, &budget)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, coded(http.StatusForbidden, mismatch)
	}
	if err != nil {
		return row, err
	}
	if claimed == nil || *claimed != rc.SAN || workload != rc.WorkloadID {
		return row, coded(http.StatusForbidden, mismatch)
	}
	if state != "claimed" || !live {
		return row, coded(http.StatusForbidden, health.CodeSessionBinding)
	}
	return row, nil
}

// lifecycleBinding fixes the runtime container from the latest mapping of
// each container interval of the certificate's Pod on its node and boot.
// Exactly one open interval with restart instance and cgroup inode is
// required (one Pod, one container: COMMON work start contract).
// SPEC-QUESTION: lifecycle_intervals has no image_manifest_digest; it is left
// null here and taken from the node witness (see ReportWorkerObservation).
func lifecycleBinding(ctx context.Context, tx pgx.Tx, rc runtimeCaller) (health.InstanceBinding, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (container_id) cluster_uid::text, container_id, restart_instance, cgroup_inode, end_quality
FROM correlation.lifecycle_intervals WHERE pod_uid=$1 AND node_uid=$2 AND boot_id=$3
ORDER BY container_id, mapping_version DESC`, rc.PodUID, rc.NodeUID, rc.BootID)
	if err != nil {
		return health.InstanceBinding{}, err
	}
	defer rows.Close()
	var found []health.InstanceBinding
	for rows.Next() {
		var cluster, container, quality string
		var restart *int32
		var cgroup *int64
		if err := rows.Scan(&cluster, &container, &restart, &cgroup, &quality); err != nil {
			return health.InstanceBinding{}, err
		}
		if quality != "open" {
			continue
		}
		if restart == nil || cgroup == nil {
			return health.InstanceBinding{}, errNotReadyPod
		}
		found = append(found, health.InstanceBinding{ClusterUID: cluster, PodUID: rc.PodUID, NodeUID: rc.NodeUID, BootID: rc.BootID,
			ContainerID: container, RestartInstance: int64(*restart), CgroupInode: *cgroup})
	}
	if err := rows.Err(); err != nil {
		return health.InstanceBinding{}, err
	}
	if len(found) != 1 {
		return health.InstanceBinding{}, errNotReadyPod
	}
	return found[0], nil
}

// expectedRuleHash is the active_version the node's live node-sensors lease
// reports. SPEC-QUESTION: no spec field names the expected rule hash of a
// node; null means the challenge carries none.
func expectedRuleHash(ctx context.Context, tx pgx.Tx, node, boot string) (*string, error) {
	var v *string
	err := tx.QueryRow(ctx, `SELECT active_version FROM health.control_health_leases
WHERE component='node-sensors' AND scope='node' AND scope_id=$1 AND boot_id=$2 AND lease_until>statement_timestamp()
ORDER BY reported_at DESC LIMIT 1`, node, boot).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return v, err
}

// activeEpoch reads release.active_policy of this environment (TASK-14; its
// migration grants control_health_writer SELECT). The row is not locked:
// FOR SHARE needs UPDATE, which COMMON does not give control_health_writer.
// SPEC-QUESTION: COMMON's lock order starts at active_policy, but only the
// coordinator has a lock function for it.
func (s *Store) activeEpoch(ctx context.Context, tx pgx.Tx) (int64, error) {
	if s.Config.Environment == "" {
		return 0, errUnavailable
	}
	var readable bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='release' AND c.relname='active_policy' AND has_schema_privilege(n.oid,'USAGE') AND has_table_privilege(c.oid,'SELECT'))`).Scan(&readable); err != nil {
		return 0, err
	}
	if !readable {
		return 0, errUnavailable
	}
	var epoch int64
	err := tx.QueryRow(ctx, `SELECT epoch FROM release.active_policy WHERE scope_id=$1`, s.Config.Environment).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, errUnavailable
	}
	return epoch, err
}

// openHolds returns the reasons of unreleased holds on the global, node,
// workload or session scope of a check, in hold_id order (COMMON lock order).
func openHolds(ctx context.Context, tx pgx.Tx, node, workload, session, lock string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT reason FROM health.holds WHERE released_at IS NULL AND (scope='global'
 OR (scope='node' AND scope_id=$1) OR (scope='workload' AND scope_id=$2) OR (scope='session' AND scope_id=$3))
ORDER BY hold_id `+lock, node, workload, session)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func uniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func nodeUUID(id string) pgtype.UUID {
	var u pgtype.UUID
	_ = u.Scan(id)
	return u
}

// auditBusiness appends one TASK-10 business event of a session in the
// caller's transaction and returns its event_id.
func (s *Store) auditBusiness(ctx context.Context, q *healthdb.Queries, kind, tenant, session, workload string, payload map[string]any, now time.Time, refs []string) (string, error) {
	if s.Epoch == "" {
		return "", errors.New("producer epoch unavailable")
	}
	if refs == nil {
		refs = []string{}
	}
	id := uuid.NewString()
	event := map[string]any{"event_id": id, "event_type": kind, "tenant": tenant, "source_id": s.Config.AuditSourceID,
		"source_version": s.Config.Version, "source_epoch": s.Epoch, "source_sequence": nil,
		"source_time": now.UTC().Format(time.RFC3339Nano), "schema_version": 1, "session_id": session, "workload_id": workload,
		"safe_payload": payload, "evidence_refs": refs}
	raw, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	digest, err := canonical.PayloadDigest(raw)
	if err != nil {
		return "", err
	}
	event["payload_digest"] = digest
	if raw, err = json.Marshal(event); err != nil {
		return "", err
	}
	result, err := q.AppendAudit(ctx, raw)
	if err != nil {
		return "", err
	}
	if result != "created" {
		return "", errors.New("health audit append did not create event")
	}
	return id, nil
}

func workerPayload(b bindingRow, state string, refs, codes []string) map[string]any {
	if codes == nil {
		codes = []string{}
	}
	return map[string]any{"worker_binding_id": b.ID, "worker_instance_id": b.InstanceID, "session_id": b.SessionID,
		"runtime_process_epoch": b.Epoch, "state": state, "evidence_refs": refs, "reason_codes": codes}
}

func registrationDigest(rc runtimeCaller, r health.WorkerRegistration) (string, error) {
	return canonical.CanonicalDigest(map[string]any{"caller_identity": rc.SAN, "session_id": r.SessionID,
		"worker_instance_id": r.WorkerInstanceID, "runtime_process_epoch": r.RuntimeProcessEpoch,
		"supervisor_process_hint": r.SupervisorProcessHint, "worker_process_hint": r.WorkerProcessHint,
		"isolation_profile_digest": r.IsolationProfileDigest, "controls_report": r.ControlsReport})
}

// issueWorkerChallenge assigns a fresh nonce for a pending binding on its
// node and current boot (TASK-10 chapter 4 pending_worker_observation_challenges).
func issueWorkerChallenge(ctx context.Context, tx pgx.Tx, binding string, ib health.InstanceBinding, generation int64, now time.Time) error {
	rule, err := expectedRuleHash(ctx, tx, ib.NodeUID, ib.BootID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO health.worker_challenges(challenge_id,kind,worker_binding_id,node_uid,boot_id,expected_sensor_generation,rule_hash,issued_at,deadline)
VALUES($1,'worker_observation',$2,$3,$4,$5,$6,$7,$8)`, uuid.NewString(), binding, ib.NodeUID, ib.BootID, generation, rule, now, now.Add(health.ChallengeTimeout))
	return err
}

func (s *Store) RegisterWorker(ctx context.Context, gateway health.Peer, callerSAN, session string, r health.WorkerRegistration) (health.WorkerBinding, error) {
	var out health.WorkerBinding
	// The registration's session must be the one the gateway verified from
	// the session token (review #228/#229): a Pod cannot register a worker
	// against another session it names in the body.
	if r.SessionID != session {
		return out, coded(http.StatusForbidden, health.CodeWorkerMismatch)
	}
	tx, q, err := s.beginWrite(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	if err := requireGateway(ctx, q, gateway); err != nil {
		return out, err
	}
	rc, err := lookupRuntime(ctx, tx, callerSAN)
	if err != nil {
		return out, err
	}
	sess, err := lookupSession(ctx, tx, r.SessionID, rc, health.CodeWorkerMismatch)
	if err != nil {
		return out, err
	}
	digest, err := registrationDigest(rc, r)
	if err != nil {
		return out, health.ErrInvalid
	}
	existing, err := scanBinding(tx.QueryRow(ctx, `SELECT `+bindingColumns+` FROM health.session_process_bindings WHERE worker_instance_id=$1 FOR UPDATE`, r.WorkerInstanceID))
	switch {
	case err == nil:
		// Same worker_instance_id and registration digest: same binding.
		if existing.RegistrationDigest != digest {
			return out, coded(http.StatusConflict, health.CodeRegistrationConflict)
		}
		return existing.public(), tx.Commit(ctx)
	case !errors.Is(err, pgx.ErrNoRows):
		return out, err
	}
	var active bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM health.session_process_bindings WHERE session_id=$1 AND state IN ('pending','observed'))`, r.SessionID).Scan(&active); err != nil {
		return out, err
	}
	if active {
		return out, coded(http.StatusConflict, health.CodeRegistrationConflict)
	}
	ib, err := lifecycleBinding(ctx, tx, rc)
	if err != nil {
		return out, err
	}
	current, err := currentNode(ctx, q, nodeUUID(ib.NodeUID))
	if err != nil || current.BootID != ib.BootID {
		return out, errNotReadyPod
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return out, err
	}
	now := clock.Time
	b := bindingRow{ID: uuid.NewString(), InstanceID: r.WorkerInstanceID, SessionID: r.SessionID, WorkloadID: rc.WorkloadID,
		Caller: rc.SAN, Epoch: r.RuntimeProcessEpoch, State: "pending", RegisteredAt: now, Instance: &ib}
	controls := uuid.NewString()
	refs := []string{"worker_evidence:" + controls}
	auditID, err := s.auditBusiness(ctx, q, "session_worker_registered", sess.Tenant, r.SessionID, rc.WorkloadID, workerPayload(b, "pending", refs, nil), now, refs)
	if err != nil {
		return out, err
	}
	b.AuditEventRef = auditID
	_, err = tx.Exec(ctx, `INSERT INTO health.session_process_bindings(worker_binding_id,worker_instance_id,session_id,workload_id,caller_identity,
 runtime_process_epoch,supervisor_process_hint,worker_process_hint,isolation_profile_digest,controls_report_ref,registration_digest,
 instance_binding,state,registered_at,audit_event_ref)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',$13,$14)`, b.ID, b.InstanceID, b.SessionID, b.WorkloadID, b.Caller, b.Epoch,
		mustJSON(r.SupervisorProcessHint), mustJSON(r.WorkerProcessHint), r.IsolationProfileDigest, controls, digest, mustJSON(ib), now, auditID)
	if uniqueViolation(err) {
		// A concurrent registration for this session or worker won.
		return out, coded(http.StatusConflict, health.CodeRegistrationConflict)
	}
	if err != nil {
		return out, err
	}
	controlsDigest, err := canonical.CanonicalDigestJSON(r.ControlsReport)
	if err != nil {
		return out, health.ErrInvalid
	}
	if _, err := tx.Exec(ctx, `INSERT INTO health.worker_evidence(evidence_id,kind,worker_binding_id,reporter_san,body,body_digest,received_at)
VALUES($1,'controls_report',$2,$3,$4,$5,$6)`, controls, b.ID, rc.SAN, []byte(r.ControlsReport), controlsDigest, now); err != nil {
		return out, err
	}
	if err := issueWorkerChallenge(ctx, tx, b.ID, ib, current.SensorGeneration, now); err != nil {
		return out, err
	}
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return b.public(), nil
}

func (s *Store) GetWorker(ctx context.Context, gateway health.Peer, callerSAN, session, id string) (health.WorkerBinding, error) {
	var out health.WorkerBinding
	tx, q, err := s.beginWrite(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	if err := requireGateway(ctx, q, gateway); err != nil {
		return out, err
	}
	b, err := selectBinding(ctx, tx, id, "FOR UPDATE")
	if err != nil {
		return out, err
	}
	if b.Caller != callerSAN || b.SessionID != session {
		// Same Pod can hold several sessions' workers with one identity, so
		// the session_id must also match or one session could read another
		// session's worker (review #228).
		return out, coded(http.StatusForbidden, health.CodeWorkerMismatch)
	}
	if b.State == "pending" && b.Instance != nil {
		// A timed-out nonce gets a new one on the same pending binding; old
		// results are never reused (TASK-10 chapter 4).
		var live bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM health.worker_challenges WHERE worker_binding_id=$1 AND kind='worker_observation' AND deadline>statement_timestamp())`, b.ID).Scan(&live); err != nil {
			return out, err
		}
		if !live {
			current, err := currentNode(ctx, q, nodeUUID(b.Instance.NodeUID))
			if err == nil && current.BootID == b.Instance.BootID {
				clock, err := q.Clock(ctx)
				if err != nil {
					return out, err
				}
				if err := issueWorkerChallenge(ctx, tx, b.ID, *b.Instance, current.SensorGeneration, clock.Time); err != nil {
					return out, err
				}
			} else if err != nil && !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, pgx.ErrTooManyRows) {
				return out, err
			}
		}
	}
	return b.public(), tx.Commit(ctx)
}

// endPendingChecks moves the binding's pending checks to expired in the
// binding's transaction (after the binding lock, COMMON lock order).
func (s *Store) endPendingChecks(ctx context.Context, tx pgx.Tx, q *healthdb.Queries, tenant string, b bindingRow, code string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT check_id::text FROM health.work_readiness_checks WHERE worker_binding_id=$1 AND state='pending' ORDER BY check_id`, b.ID)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, id := range ids {
		c, err := selectCheck(ctx, tx, id, "FOR UPDATE OF c")
		if err != nil {
			return err
		}
		if c.State != "pending" {
			continue
		}
		if err := s.finishCheck(ctx, tx, q, tenant, c, "expired", []string{code}, nil, now, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CloseWorker(ctx context.Context, gateway health.Peer, callerSAN, session, id string, r health.WorkerClose) (health.WorkerBinding, error) {
	var out health.WorkerBinding
	tx, q, err := s.beginWrite(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	if err := requireGateway(ctx, q, gateway); err != nil {
		return out, err
	}
	b, err := selectBinding(ctx, tx, id, "FOR UPDATE")
	if err != nil {
		return out, err
	}
	if b.Caller != callerSAN || b.SessionID != session {
		// A close must not act on another session's worker on the same Pod
		// (review #228): the session_id is checked before the state so a
		// cross-session close is rejected even for an already-closed binding.
		return out, coded(http.StatusForbidden, health.CodeWorkerMismatch)
	}
	if b.State == "closed" || b.State == "invalidated" {
		// Idempotent close; the original evidence is kept.
		return b.public(), tx.Commit(ctx)
	}
	var tenant string
	if err := tx.QueryRow(ctx, `SELECT tenant FROM identity.work_readiness_session_view WHERE session_id=$1`, b.SessionID).Scan(&tenant); err != nil {
		return out, err
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return out, err
	}
	now := clock.Time
	evidence := uuid.NewString()
	body := mustJSON(r)
	digest, err := canonical.CanonicalDigestJSON(body)
	if err != nil {
		return out, health.ErrInvalid
	}
	if _, err := tx.Exec(ctx, `INSERT INTO health.worker_evidence(evidence_id,kind,worker_binding_id,reporter_san,body,body_digest,received_at)
VALUES($1,'close_report',$2,$3,$4,$5,$6)`, evidence, b.ID, callerSAN, body, digest, now); err != nil {
		return out, err
	}
	refs := []string{"worker_evidence:" + evidence}
	// SPEC-QUESTION: close has no SessionProcessBinding reason code; the
	// supervisor's reason stays in the close_report evidence.
	if _, err := s.auditBusiness(ctx, q, "session_worker_closed", tenant, b.SessionID, b.WorkloadID, workerPayload(b, "closed", refs, nil), now, refs); err != nil {
		return out, err
	}
	if _, err := tx.Exec(ctx, `UPDATE health.session_process_bindings SET state='closed', ended_at=$2 WHERE worker_binding_id=$1`, b.ID, now); err != nil {
		return out, err
	}
	if err := s.endPendingChecks(ctx, tx, q, tenant, b, health.CodeWorkerExited, now); err != nil {
		return out, err
	}
	b.State, b.EndedAt = "closed", &now
	return b.public(), tx.Commit(ctx)
}

// invalidateBinding closes new work for a binding whose sensor generation or
// instance no longer holds (COMMON multiple sessions, restart and failure).
func (s *Store) invalidateBinding(ctx context.Context, tx pgx.Tx, q *healthdb.Queries, tenant string, b bindingRow, code string, now time.Time) error {
	if b.State != "pending" && b.State != "observed" {
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE health.session_process_bindings SET state='invalidated', ended_at=$2, reason_codes=$3 WHERE worker_binding_id=$1`, b.ID, now, []string{code}); err != nil {
		return err
	}
	if _, err := s.auditBusiness(ctx, q, "session_worker_invalidated", tenant, b.SessionID, b.WorkloadID, workerPayload(b, "invalidated", []string{}, []string{code}), now, nil); err != nil {
		return err
	}
	return s.endPendingChecks(ctx, tx, q, tenant, b, code, now)
}

type challengeRow struct {
	ID, Kind, Binding  string
	CheckID            *string
	Node, Boot         string
	Generation         int64
	RuleHash           *string
	IssuedAt, Deadline time.Time
	EvidenceDigest     *string
	EvidenceID         *string
	EvidenceReceivedAt *time.Time
}

func selectChallenge(ctx context.Context, tx pgx.Tx, id string) (challengeRow, error) {
	var c challengeRow
	err := tx.QueryRow(ctx, `SELECT g.challenge_id::text, g.kind, g.worker_binding_id::text, g.check_id::text, g.node_uid::text, g.boot_id,
 g.expected_sensor_generation, g.rule_hash, g.issued_at, g.deadline, e.body_digest, e.evidence_id::text, e.received_at
FROM health.worker_challenges g LEFT JOIN health.worker_evidence e ON e.challenge_id=g.challenge_id WHERE g.challenge_id=$1`, id).Scan(
		&c.ID, &c.Kind, &c.Binding, &c.CheckID, &c.Node, &c.Boot, &c.Generation, &c.RuleHash, &c.IssuedAt, &c.Deadline,
		&c.EvidenceDigest, &c.EvidenceID, &c.EvidenceReceivedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, health.ErrNotFound
	}
	return c, err
}

// nodeResultFresh bounds a node answer by server time: reported after the
// nonce was issued, not in the future, at most MaxResultAge old on receipt
// and received before the challenge deadline (COMMON Pod readiness check and freshness).
func nodeResultFresh(reported time.Time, c challengeRow, now time.Time) bool {
	const skew = 2 * time.Second
	return !now.After(c.Deadline) && !reported.Before(c.IssuedAt.Add(-skew)) && !reported.After(now.Add(skew)) &&
		now.Sub(reported) <= health.MaxResultAge
}

// replayAck answers a re-report of the same nonce: the same digest is the
// stored ack, another body is a conflict.
func replayAck(c challengeRow, digest string) (health.EvidenceAck, bool, error) {
	if c.EvidenceDigest == nil {
		return health.EvidenceAck{}, false, nil
	}
	if *c.EvidenceDigest != digest {
		return health.EvidenceAck{}, true, coded(http.StatusConflict, health.CodeEventIDConflict)
	}
	return health.EvidenceAck{EvidenceID: *c.EvidenceID, Result: "existing", ReceivedAt: *c.EvidenceReceivedAt}, true, nil
}

type execEvidence struct {
	ExecID           string
	ParentExecID     *string
	HostPID          int64
	ProcessStart     *time.Time
	SensorGeneration int64
	SamePIDExecs     int64
	Exited           bool
}

func (s *Store) ReportWorkerObservation(ctx context.Context, sensor health.Peer, r health.WorkerObservationResult) (health.EvidenceAck, error) {
	var ack health.EvidenceAck
	tx, q, err := s.beginWrite(ctx)
	if err != nil {
		return ack, err
	}
	defer rollback(tx)
	current, err := requireSensor(ctx, q, sensor)
	if err != nil {
		return ack, err
	}
	c, err := selectChallenge(ctx, tx, r.ChallengeID)
	if err != nil {
		return ack, err
	}
	node := uuid.UUID(current.NodeUid.Bytes).String()
	if c.Kind != "worker_observation" || c.Node != node || c.Boot != current.BootID {
		return ack, health.ErrForbidden
	}
	if c.Binding != r.WorkerBindingID {
		return ack, coded(http.StatusConflict, health.CodeWorkerMismatch)
	}
	body := mustJSON(r)
	digest, err := canonical.CanonicalDigestJSON(body)
	if err != nil {
		return ack, health.ErrInvalid
	}
	if ack, done, err := replayAck(c, digest); done {
		return ack, err
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return ack, err
	}
	now := clock.Time
	if !nodeResultFresh(r.ReportedAt, c, now) {
		return ack, coded(http.StatusConflict, health.CodeWorkerNotReady)
	}
	b, err := selectBinding(ctx, tx, c.Binding, "FOR UPDATE")
	if err != nil {
		return ack, err
	}
	if b.State != "pending" || b.Instance == nil {
		return ack, coded(http.StatusConflict, health.CodeWorkerExited)
	}
	if !r.InstanceBinding.SameLocation(*b.Instance) || r.SensorGeneration != current.SensorGeneration || r.SensorGeneration != c.Generation ||
		r.WorkerIdentity.ProcessHint != b.WorkerHint || r.SupervisorIdentity.ProcessHint != b.SupervisorHint {
		return ack, coded(http.StatusConflict, health.CodeWorkerMismatch)
	}
	if r.InstanceBinding.ImageManifestDigest == nil {
		return ack, coded(http.StatusConflict, health.CodePodNotReady)
	}
	if !r.WorkerAlive {
		return ack, coded(http.StatusConflict, health.CodeWorkerExited)
	}
	// The worker's final exec must be one committed kernel row of this node,
	// boot and container with the witnessed host PID and exec ID.
	var ev execEvidence
	err = tx.QueryRow(ctx, `SELECT process_exec_id, parent_exec_id, host_pid, process_start, sensor_generation, same_pid_execs, exited
FROM audit.worker_exec_evidence($1,$2,$3,$4)`, r.ExecEventRef, node, current.BootID, b.Instance.ContainerID).Scan(
		&ev.ExecID, &ev.ParentExecID, &ev.HostPID, &ev.ProcessStart, &ev.SensorGeneration, &ev.SamePIDExecs, &ev.Exited)
	if errors.Is(err, pgx.ErrNoRows) {
		// Not committed yet (or not this container): retry within the nonce.
		return ack, errNotReadyWorker
	}
	if err != nil {
		return ack, err
	}
	if ev.ExecID != r.RootExecID || ev.HostPID != r.WorkerIdentity.HostPID || ev.SamePIDExecs != 1 || ev.ParentExecID == nil ||
		ev.ProcessStart == nil || ev.SensorGeneration != current.SensorGeneration {
		return ack, coded(http.StatusConflict, health.CodeWorkerMismatch)
	}
	if ev.Exited {
		return ack, coded(http.StatusConflict, health.CodeWorkerExited)
	}
	var tenant string
	if err := tx.QueryRow(ctx, `SELECT tenant FROM identity.work_readiness_session_view WHERE session_id=$1`, b.SessionID).Scan(&tenant); err != nil {
		return ack, err
	}
	evidence := uuid.NewString()
	if _, err := tx.Exec(ctx, `INSERT INTO health.worker_evidence(evidence_id,kind,worker_binding_id,challenge_id,reporter_san,body,body_digest,reported_at,received_at)
VALUES($1,'worker_observation',$2,$3,$4,$5,$6,$7,$8)`, evidence, b.ID, c.ID, sensor.SAN, body, digest, r.ReportedAt, now); err != nil {
		return ack, err
	}
	observed := *b.Instance
	observed.ImageManifestDigest = r.InstanceBinding.ImageManifestDigest
	refs := []string{"worker_evidence:" + evidence, "kernel_event:" + r.ExecEventRef}
	if _, err := s.auditBusiness(ctx, q, "session_worker_observed", tenant, b.SessionID, b.WorkloadID, workerPayload(b, "observed", refs, nil), now, refs); err != nil {
		return ack, err
	}
	_, err = tx.Exec(ctx, `UPDATE health.session_process_bindings SET state='observed', instance_binding=$2, root_exec_id=$3, host_pid=$4,
 process_start=$5, exec_event_ref=$6, node_evidence_ref=$7, sensor_generation=$8, observed_at=$9 WHERE worker_binding_id=$1`,
		b.ID, mustJSON(observed), r.RootExecID, ev.HostPID, ev.ProcessStart, r.ExecEventRef, evidence, current.SensorGeneration, now)
	if uniqueViolation(err) {
		// worker_root_exec_not_reassigned: this exec already backs another binding.
		return ack, coded(http.StatusConflict, health.CodeWorkerMismatch)
	}
	if err != nil {
		return ack, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ack, err
	}
	return health.EvidenceAck{EvidenceID: evidence, Result: "created", ReceivedAt: now}, nil
}

func (s *Store) RequestReadiness(ctx context.Context, gateway health.Peer, callerSAN, session string, r health.ReadinessRequest) (health.ReadinessCheck, error) {
	var out health.ReadinessCheck
	// The readiness request's session must be the gateway-verified one
	// (review #228/#229).
	if r.SessionID != session {
		return out, coded(http.StatusForbidden, health.CodeReadinessMismatch)
	}
	tx, q, err := s.beginWrite(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	if err := requireGateway(ctx, q, gateway); err != nil {
		return out, err
	}
	rc, err := lookupRuntime(ctx, tx, callerSAN)
	if err != nil {
		return out, err
	}
	sess, err := lookupSession(ctx, tx, r.SessionID, rc, health.CodeReadinessMismatch)
	if err != nil {
		return out, err
	}
	epoch, err := s.activeEpoch(ctx, tx)
	if err != nil {
		return out, err
	}
	current, err := currentNode(ctx, q, nodeUUID(rc.NodeUID))
	if err != nil || current.BootID != rc.BootID {
		return out, errNotReadyPod
	}
	b, err := selectBinding(ctx, tx, r.WorkerBindingID, "FOR UPDATE")
	if errors.Is(err, health.ErrNotFound) {
		return out, coded(http.StatusForbidden, health.CodeWorkerMismatch)
	}
	if err != nil {
		return out, err
	}
	if b.Caller != rc.SAN || b.SessionID != r.SessionID || b.InstanceID != r.WorkerInstanceID || b.Epoch != r.RuntimeProcessEpoch {
		return out, coded(http.StatusForbidden, health.CodeWorkerMismatch)
	}
	switch b.State {
	case "pending":
		return out, errNotReadyWorker
	case "closed", "invalidated":
		return out, errWorkerExited
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return out, err
	}
	now := clock.Time
	if b.Instance == nil || b.Instance.NodeUID != rc.NodeUID || b.Instance.BootID != rc.BootID || b.SensorGeneration == nil {
		return out, coded(http.StatusForbidden, health.CodeWorkerMismatch)
	}
	if *b.SensorGeneration != current.SensorGeneration {
		// A sensor generation change invalidates the binding; the next worker
		// needs a new binding and exec.
		if err := s.invalidateBinding(ctx, tx, q, sess.Tenant, b, health.CodeWorkerMismatch, now); err != nil {
			return out, err
		}
		if err := tx.Commit(ctx); err != nil {
			return out, err
		}
		return out, coded(http.StatusServiceUnavailable, health.CodeWorkerMismatch)
	}
	rule, err := expectedRuleHash(ctx, tx, rc.NodeUID, rc.BootID)
	if err != nil {
		return out, err
	}
	gen := current.SensorGeneration
	c := health.ReadinessCheck{CheckID: uuid.NewString(), WorkRunID: r.WorkRunID, Checkpoint: r.Checkpoint, SessionID: r.SessionID,
		WorkloadID: rc.WorkloadID, CallerIdentity: rc.SAN, RuntimeProcessEpoch: r.RuntimeProcessEpoch, WorkerInstanceID: b.InstanceID,
		WorkerBindingID: b.ID, RootExecID: b.RootExecID, WorkerEvidenceRefs: b.public().EvidenceRefs, InstanceBinding: b.Instance,
		SensorGeneration: &gen, RuleHash: rule, PolicyEpoch: &epoch, ChallengeEvidenceRefs: []string{}, State: "pending",
		ReasonCodes: []string{}, CreatedAt: now}
	challenge := uuid.NewString()
	c.ChallengeID = &challenge
	auditID, err := s.auditBusiness(ctx, q, "work_readiness_requested", sess.Tenant, c.SessionID, c.WorkloadID, checkPayload(c, nil), now, c.WorkerEvidenceRefs)
	if err != nil {
		return out, err
	}
	c.AuditEventRef = auditID
	if _, err := tx.Exec(ctx, `INSERT INTO health.work_readiness_checks(check_id,work_run_id,checkpoint,session_id,workload_id,caller_identity,
 runtime_process_epoch,worker_instance_id,worker_binding_id,root_exec_id,worker_evidence_refs,instance_binding,sensor_generation,rule_hash,
 policy_epoch,challenge_id,state,created_at,audit_event_ref)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'pending',$17,$18)`, c.CheckID, c.WorkRunID, c.Checkpoint, c.SessionID,
		c.WorkloadID, c.CallerIdentity, c.RuntimeProcessEpoch, c.WorkerInstanceID, c.WorkerBindingID, c.RootExecID, mustJSON(c.WorkerEvidenceRefs),
		mustJSON(c.InstanceBinding), gen, rule, epoch, challenge, now, auditID); err != nil {
		return out, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO health.worker_challenges(challenge_id,kind,worker_binding_id,check_id,node_uid,boot_id,expected_sensor_generation,rule_hash,issued_at,deadline)
VALUES($1,'work_readiness',$2,$3,$4,$5,$6,$7,$8,$9)`, challenge, b.ID, c.CheckID, rc.NodeUID, rc.BootID, gen, rule, now, now.Add(health.ChallengeTimeout)); err != nil {
		return out, err
	}
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return c, nil
}

func checkPayload(c health.ReadinessCheck, refs []string) map[string]any {
	if refs == nil {
		refs = c.WorkerEvidenceRefs
	}
	var ib any = map[string]any{}
	if c.InstanceBinding != nil {
		ib = c.InstanceBinding
	}
	return map[string]any{"check_id": c.CheckID, "work_run_id": c.WorkRunID, "checkpoint": c.Checkpoint, "session_id": c.SessionID,
		"workload_id": c.WorkloadID, "worker_instance_id": c.WorkerInstanceID, "worker_binding_id": c.WorkerBindingID,
		"root_exec_id": c.RootExecID, "instance_binding": ib, "sensor_generation": c.SensorGeneration, "policy_epoch": c.PolicyEpoch,
		"reason_codes": c.ReasonCodes, "evidence_refs": refs, "checked_at": c.CheckedAt}
}

// finishCheck moves a pending check to ready, blocked or expired with its
// audit event in the same transaction. ready carries expires and the
// challenge evidence.
func (s *Store) finishCheck(ctx context.Context, tx pgx.Tx, q *healthdb.Queries, tenant string, c checkRow, state string, codes, challengeRefs []string, now time.Time, expires *time.Time) error {
	if codes == nil {
		codes = []string{}
	}
	if challengeRefs == nil {
		challengeRefs = c.ChallengeEvidenceRefs
	}
	c.State, c.ReasonCodes, c.CheckedAt = state, codes, &now
	kind := "work_readiness_blocked"
	if state == "ready" {
		kind = "work_readiness_passed"
	}
	refs := append(append([]string{}, c.WorkerEvidenceRefs...), challengeRefs...)
	auditID, err := s.auditBusiness(ctx, q, kind, tenant, c.SessionID, c.WorkloadID, checkPayload(c.ReadinessCheck, refs), now, refs)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE health.work_readiness_checks SET state=$2, reason_codes=$3, checked_at=$4, expires_at=$5,
 challenge_evidence_refs=$6, rule_hash=$7, audit_event_ref=$8 WHERE check_id=$1 AND state='pending'`,
		c.CheckID, state, codes, now, expires, mustJSON(challengeRefs), c.RuleHash, auditID)
	return err
}

func (s *Store) ReportPodObservation(ctx context.Context, sensor health.Peer, r health.PodObservationResult) (health.EvidenceAck, error) {
	var ack health.EvidenceAck
	tx, q, err := s.beginWrite(ctx)
	if err != nil {
		return ack, err
	}
	defer rollback(tx)
	current, err := requireSensor(ctx, q, sensor)
	if err != nil {
		return ack, err
	}
	ch, err := selectChallenge(ctx, tx, r.ChallengeID)
	if err != nil {
		return ack, err
	}
	node := uuid.UUID(current.NodeUid.Bytes).String()
	if ch.Kind != "work_readiness" || ch.Node != node || ch.Boot != current.BootID {
		return ack, health.ErrForbidden
	}
	if ch.CheckID == nil || *ch.CheckID != r.CheckID {
		return ack, coded(http.StatusConflict, health.CodeReadinessMismatch)
	}
	body := mustJSON(r)
	digest, err := canonical.CanonicalDigestJSON(body)
	if err != nil {
		return ack, health.ErrInvalid
	}
	if ack, done, err := replayAck(ch, digest); done {
		return ack, err
	}
	// Final transaction, COMMON lock order: active_policy (read) → holds →
	// node_boot_generation → (sessions, read through the view) →
	// session_process_bindings → work_readiness_checks.
	epoch, epochErr := s.activeEpoch(ctx, tx)
	if epochErr != nil && !errors.Is(epochErr, errUnavailable) {
		return ack, epochErr
	}
	pre, err := selectCheck(ctx, tx, r.CheckID, "")
	if err != nil {
		return ack, err
	}
	holds, err := openHolds(ctx, tx, node, pre.WorkloadID, pre.SessionID, "FOR SHARE")
	if err != nil {
		return ack, err
	}
	var nodeState string
	if err := tx.QueryRow(ctx, `SELECT state FROM health.node_boot_generation WHERE node_uid=$1 AND boot_id=$2 FOR SHARE`, node, current.BootID).Scan(&nodeState); err != nil {
		return ack, err
	}
	var tenant, sessState, sessWorkload string
	var sessLive bool
	var claimed *string
	if err := tx.QueryRow(ctx, `SELECT tenant, state, expires_at>statement_timestamp(), claimed_workload_identity, workload_id
FROM identity.work_readiness_session_view WHERE session_id=$1`, pre.SessionID).Scan(&tenant, &sessState, &sessLive, &claimed, &sessWorkload); err != nil {
		return ack, err
	}
	b, err := selectBinding(ctx, tx, pre.WorkerBindingID, "FOR UPDATE")
	if err != nil {
		return ack, err
	}
	c, err := selectCheck(ctx, tx, r.CheckID, "FOR UPDATE OF c")
	if err != nil {
		return ack, err
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return ack, err
	}
	now := clock.Time
	if c.State != "pending" {
		return ack, coded(http.StatusConflict, health.CodeReadinessExpired)
	}
	if now.After(ch.Deadline) {
		if err := s.finishCheck(ctx, tx, q, tenant, c, "expired", []string{health.CodeReadinessExpired}, nil, now, nil); err != nil {
			return ack, err
		}
		if err := tx.Commit(ctx); err != nil {
			return ack, err
		}
		return ack, coded(http.StatusConflict, health.CodeReadinessExpired)
	}
	evidence := uuid.NewString()
	if _, err := tx.Exec(ctx, `INSERT INTO health.worker_evidence(evidence_id,kind,worker_binding_id,check_id,challenge_id,reporter_san,body,body_digest,reported_at,received_at)
VALUES($1,'pod_observation',$2,$3,$4,$5,$6,$7,$8,$9)`, evidence, b.ID, c.CheckID, ch.ID, sensor.SAN, body, digest, r.ReportedAt, now); err != nil {
		return ack, err
	}
	// Re-check everything the ready result depends on; any failure blocks.
	var codes []string
	add := func(code string) {
		if !slices.Contains(codes, code) {
			codes = append(codes, code)
		}
	}
	generationChanged := c.SensorGeneration == nil || *c.SensorGeneration != current.SensorGeneration || r.SensorGeneration != current.SensorGeneration
	if c.InstanceBinding == nil || !r.InstanceBinding.SameLocation(*c.InstanceBinding) || c.InstanceBinding.ImageManifestDigest == nil ||
		r.InstanceBinding.ImageManifestDigest == nil || *r.InstanceBinding.ImageManifestDigest != *c.InstanceBinding.ImageManifestDigest ||
		generationChanged || (ch.RuleHash != nil && *ch.RuleHash != r.RuleHash) || !r.FilterIncluded || !r.WALFsyncReady ||
		!nodeResultFresh(r.ReportedAt, ch, now) || nodeState != "ready" || c.InstanceBinding.BootID != current.BootID {
		add(health.CodePodNotReady)
	}
	switch {
	case b.State != "observed":
		add(health.CodeWorkerExited)
	case r.WorkerAlive == nil || !*r.WorkerAlive:
		add(health.CodeWorkerExited)
	case r.WorkerBindingID == nil || *r.WorkerBindingID != b.ID || r.RootExecID == nil || b.RootExecID == nil || *r.RootExecID != *b.RootExecID ||
		c.RootExecID == nil || *c.RootExecID != *b.RootExecID:
		add(health.CodeWorkerMismatch)
	case len(r.WorkerEvidenceRefs) == 0:
		add(health.CodeWorkerNotReady)
	}
	if epochErr != nil || c.PolicyEpoch == nil || epoch != *c.PolicyEpoch {
		add(health.CodeReadinessExpired)
	}
	if len(holds) > 0 {
		add(health.CodeHoldActive)
	}
	if claimed == nil || *claimed != c.CallerIdentity || sessWorkload != c.WorkloadID || sessState != "claimed" || !sessLive {
		add(health.CodeSessionBinding)
	}
	// Required global and node leases (TASK-10 3.2): a missing or expired
	// one is CONTROL_HEALTH_UNAVAILABLE; ready never outlives a used lease.
	expires := now.Add(health.MaxResultAge)
	if reportLimit := r.ReportedAt.Add(health.MaxResultAge); reportLimit.Before(expires) {
		expires = reportLimit
	}
	for _, scope := range [][2]string{{"global", "*"}, {"node", node}} {
		snap, err := s.snapshot(ctx, q, scope[0], scope[1], now)
		if err != nil {
			return ack, err
		}
		if len(snap.MissingComponents) > 0 {
			add(health.CodeHealthUnavailable)
		}
		for _, l := range snap.Leases {
			if l.Component != health.ComponentNetpol && l.LeaseUntil.After(now) && l.LeaseUntil.Before(expires) {
				expires = l.LeaseUntil
			}
		}
	}
	if !expires.After(now) {
		add(health.CodeReadinessExpired)
	}
	challengeRefs := append([]string{"worker_evidence:" + evidence}, r.EvidenceRefs...)
	c.RuleHash = &r.RuleHash
	if len(codes) == 0 {
		err = s.finishCheck(ctx, tx, q, tenant, c, "ready", nil, challengeRefs, now, &expires)
	} else {
		err = s.finishCheck(ctx, tx, q, tenant, c, "blocked", codes, challengeRefs, now, nil)
	}
	if err != nil {
		return ack, err
	}
	if generationChanged {
		if err := s.invalidateBinding(ctx, tx, q, tenant, b, health.CodeWorkerMismatch, now); err != nil {
			return ack, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ack, err
	}
	return health.EvidenceAck{EvidenceID: evidence, Result: "created", ReceivedAt: now}, nil
}

// GetReadiness returns the caller's own check. A ready result is re-validated
// against the current binding, generation, holds, policy epoch and session;
// any change reports it as not ready (it is never reused). The stored row
// keeps state ready because the DDL allows no ready→expired transition.
func (s *Store) GetReadiness(ctx context.Context, gateway health.Peer, callerSAN, session, id string) (health.ReadinessCheck, error) {
	var out health.ReadinessCheck
	tx, q, err := s.beginWrite(ctx)
	if err != nil {
		return out, err
	}
	defer rollback(tx)
	if err := requireGateway(ctx, q, gateway); err != nil {
		return out, err
	}
	c, err := selectCheck(ctx, tx, id, "")
	if err != nil {
		return out, err
	}
	if c.CallerIdentity != callerSAN || c.SessionID != session {
		// A check belongs to one session; another session on the same Pod
		// must not read it (review #228).
		return out, coded(http.StatusForbidden, health.CodeReadinessMismatch)
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return out, err
	}
	now := clock.Time
	switch c.State {
	case "pending":
		if !now.After(c.Deadline) {
			return c.ReadinessCheck, tx.Commit(ctx)
		}
		var tenant string
		if err := tx.QueryRow(ctx, `SELECT tenant FROM identity.work_readiness_session_view WHERE session_id=$1`, c.SessionID).Scan(&tenant); err != nil {
			return out, err
		}
		locked, err := selectCheck(ctx, tx, id, "FOR UPDATE OF c")
		if err != nil {
			return out, err
		}
		if locked.State == "pending" {
			if err := s.finishCheck(ctx, tx, q, tenant, locked, "expired", []string{health.CodeReadinessExpired}, nil, now, nil); err != nil {
				return out, err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return out, err
		}
		final, err := s.readCheck(ctx, id)
		return final, err
	case "ready":
		codes, err := s.revalidate(ctx, tx, q, c, now)
		if err != nil {
			return out, err
		}
		if len(codes) > 0 {
			c.State, c.ReasonCodes = "expired", codes
			if slices.Contains(codes, health.CodeHoldActive) {
				c.State = "blocked"
			}
		} else {
			c.RemainingValidMS = c.ExpiresAt.Sub(now).Milliseconds()
			if c.RemainingValidMS <= 0 {
				c.State, c.ReasonCodes, c.RemainingValidMS = "expired", []string{health.CodeReadinessExpired}, 0
			}
		}
	}
	return c.ReadinessCheck, tx.Commit(ctx)
}

func (s *Store) readCheck(ctx context.Context, id string) (health.ReadinessCheck, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return health.ReadinessCheck{}, err
	}
	defer rollback(tx)
	c, err := selectCheck(ctx, tx, id, "")
	return c.ReadinessCheck, err
}

func (s *Store) revalidate(ctx context.Context, tx pgx.Tx, q *healthdb.Queries, c checkRow, now time.Time) ([]string, error) {
	var codes []string
	if c.ExpiresAt == nil || !c.ExpiresAt.After(now) {
		return []string{health.CodeReadinessExpired}, nil
	}
	b, err := selectBinding(ctx, tx, c.WorkerBindingID, "")
	if err != nil {
		return nil, err
	}
	if b.State != "observed" || b.RootExecID == nil || c.RootExecID == nil || *b.RootExecID != *c.RootExecID {
		codes = append(codes, health.CodeWorkerExited)
	}
	if c.InstanceBinding == nil {
		return []string{health.CodePodNotReady}, nil
	}
	current, err := currentNode(ctx, q, nodeUUID(c.InstanceBinding.NodeUID))
	if err != nil || current.BootID != c.InstanceBinding.BootID || c.SensorGeneration == nil || current.SensorGeneration != *c.SensorGeneration {
		codes = append(codes, health.CodePodNotReady)
	}
	if epoch, err := s.activeEpoch(ctx, tx); err != nil || c.PolicyEpoch == nil || epoch != *c.PolicyEpoch {
		if err != nil && !errors.Is(err, errUnavailable) {
			return nil, err
		}
		codes = append(codes, health.CodeReadinessExpired)
	}
	holds, err := openHolds(ctx, tx, c.InstanceBinding.NodeUID, c.WorkloadID, c.SessionID, "")
	if err != nil {
		return nil, err
	}
	if len(holds) > 0 {
		codes = append(codes, health.CodeHoldActive)
	}
	var state string
	var live bool
	var claimed *string
	err = tx.QueryRow(ctx, `SELECT state, expires_at>statement_timestamp(), claimed_workload_identity FROM identity.work_readiness_session_view WHERE session_id=$1`, c.SessionID).Scan(&state, &live, &claimed)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err != nil || state != "claimed" || !live || claimed == nil || *claimed != c.CallerIdentity {
		codes = append(codes, health.CodeSessionBinding)
	}
	return codes, nil
}

// nodeChallenges lists the open nonces of one node boot for its node-sensors
// (TASK-10 chapter 4 pending_*_challenges). Answered or timed-out nonces are not
// listed again.
func nodeChallenges(ctx context.Context, tx pgx.Tx, node, boot string) ([]json.RawMessage, []json.RawMessage, error) {
	workers := []json.RawMessage{}
	checks := []json.RawMessage{}
	rows, err := tx.Query(ctx, `SELECT g.kind, g.challenge_id::text, g.worker_binding_id::text, g.check_id::text, g.expected_sensor_generation,
 g.rule_hash, g.deadline, b.instance_binding, b.supervisor_process_hint, b.worker_process_hint, b.isolation_profile_digest, b.root_exec_id,
 c.instance_binding
FROM health.worker_challenges g
JOIN health.session_process_bindings b ON b.worker_binding_id=g.worker_binding_id
LEFT JOIN health.work_readiness_checks c ON c.check_id=g.check_id
WHERE g.node_uid=$1 AND g.boot_id=$2 AND g.deadline>statement_timestamp()
  AND NOT EXISTS (SELECT 1 FROM health.worker_evidence e WHERE e.challenge_id=g.challenge_id)
  AND ((g.kind='worker_observation' AND b.state='pending') OR (g.kind='work_readiness' AND c.state='pending'))
ORDER BY g.issued_at, g.challenge_id`, node, boot)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, challenge, binding, isolation string
		var check, rule, root *string
		var gen int64
		var deadline time.Time
		var bInst, sup, wrk, cInst []byte
		if err := rows.Scan(&kind, &challenge, &binding, &check, &gen, &rule, &deadline, &bInst, &sup, &wrk, &isolation, &root, &cInst); err != nil {
			return nil, nil, err
		}
		if kind == "worker_observation" {
			ch := health.WorkerObservationChallenge{WorkerBindingID: binding, ChallengeID: challenge, IsolationProfileDigest: isolation,
				ExpectedSensorGeneration: gen, RuleHash: rule, Deadline: deadline}
			if json.Unmarshal(bInst, &ch.InstanceBinding) != nil || json.Unmarshal(sup, &ch.SupervisorProcessHint) != nil || json.Unmarshal(wrk, &ch.WorkerProcessHint) != nil {
				return nil, nil, errors.New("stored challenge unreadable")
			}
			workers = append(workers, mustJSON(ch))
			continue
		}
		ch := health.ReadinessChallenge{CheckID: *check, ChallengeID: challenge, ExpectedSensorGeneration: gen, RuleHash: rule,
			WorkerBindingID: binding, Deadline: deadline}
		if root != nil {
			ch.RootExecID = *root
		}
		if json.Unmarshal(cInst, &ch.InstanceBinding) != nil {
			return nil, nil, errors.New("stored challenge unreadable")
		}
		checks = append(checks, mustJSON(ch))
	}
	return workers, checks, rows.Err()
}
