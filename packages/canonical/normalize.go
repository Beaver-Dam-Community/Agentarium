package canonical

import (
	"encoding/json"
)

// Server constants of the action_digest limits (TASK-02 3.3 table).
// SPEC-QUESTION: the same values can also appear in the catalog (limits.limit.fixed,
// response_limit_bytes); action_digest uses these table constants, not the catalog copies.
const (
	K8sListLimit         = 100
	K8sListResponseBytes = 1048576
	ReadResponseBytes    = 65536 // evidence.* and discovery.*
)

// DecodeClientAction strictly reads the outer ClientAction from the raw body
// (TASK-02 3.1). Errors carry an empty RuleID: no action can be created.
func DecodeClientAction(raw []byte) (ClientAction, *NormalizeError) {
	if len(raw) > MaxBodyBytes {
		return ClientAction{}, &NormalizeError{ReasonCodes: []string{ReasonBodyTooLarge}, HTTPStatus: 413, Detail: "body exceeds 1 MiB"}
	}
	var ca ClientAction
	if err := decodeStrict(raw, &ca); err != nil {
		return ClientAction{}, schemaErr("", "%v", err)
	}
	if !isUUID(ca.SessionID) {
		return ClientAction{}, schemaErr("", "session_id must be a lowercase UUID")
	}
	if !reClientRequestKey.MatchString(ca.ClientRequestKey) {
		return ClientAction{}, schemaErr("", "client_request_key must match [A-Za-z0-9_-]{8,64}")
	}
	if ca.OperationID == "" {
		return ClientAction{}, schemaErr("", "operation_id must be non-empty")
	}
	return ca, nil
}

// opResult is what an operation-specific normalizer contributes.
type opResult struct {
	target       CatalogTarget
	canonical    CanonicalTarget
	limits       map[string]int64
	disclosure   []string
	contentInput any // nil when content_digest is null
}

// Normalize is the network-free normalizer (TASK-02 3.3, 4). action must come
// from DecodeClientAction(raw). It validates the operation typed schema,
// resolves the registered target, runs the content checker and computes the
// envelope including action_digest. Content is zero for operations without content.
func Normalize(action ClientAction, raw []byte, trusted TrustedContext, cat Catalog) (ActionEnvelope, Content, *NormalizeError) {
	if err := checkTrusted(trusted, cat); err != nil {
		return ActionEnvelope{}, Content{}, err
	}
	op, ok := cat.Operations[action.OperationID]
	if !ok {
		return ActionEnvelope{}, Content{}, notRegisteredErr("operation_id %q is not in the catalog", action.OperationID)
	}
	lookup := func(id string) (CatalogTarget, *NormalizeError) {
		t, ok := cat.Targets[id]
		if !ok || !contains(t.OperationIDs, op.OperationID) {
			return CatalogTarget{}, notRegisteredErr("target_id %q is not registered for %s", id, op.OperationID)
		}
		return t, nil
	}
	var res opResult
	var nerr *NormalizeError
	switch op.OperationID {
	case OpK8sPodsList, OpK8sEventsList:
		res, nerr = normK8sList(action, op, lookup)
	case OpK8sPodsLogs:
		res, nerr = normK8sLogs(action, op, lookup)
	case OpReceiverSubmit:
		res, nerr = normReceiver(action, op, lookup)
	case OpModelGenerate:
		res, nerr = normModel(action, op, cat, lookup)
	case OpEvidenceActionRead, OpEvidenceBundleRead, OpEvidenceRegressionRead:
		res, nerr = normEvidence(action, op, lookup)
	case OpDiscoverySourceRead:
		res, nerr = normDiscoverySource(action, op, lookup)
	case OpDiscoveryCallgraphRead:
		res, nerr = normDiscoveryCallgraph(action, op, lookup)
	default:
		nerr = notRegisteredErr("operation_id %q has no typed ClientAction schema", op.OperationID)
	}
	if nerr != nil {
		return ActionEnvelope{}, Content{}, nerr
	}
	res.canonical.TargetID = res.target.TargetID
	res.canonical.RouteID = op.RouteID

	disclosure, err := SortSet(res.disclosure)
	if err != nil {
		return ActionEnvelope{}, Content{}, schemaErr(RuleSchema, "disclosure_fields: %v", err)
	}
	if disclosure == nil {
		disclosure = []string{}
	}

	var content Content
	var contentDigest *string
	if res.contentInput != nil {
		b, err := CanonicalJSON(res.contentInput)
		if err != nil {
			return ActionEnvelope{}, Content{}, schemaErr(RuleSchema, "content: %v", err)
		}
		d := SHA256Hex(b)
		contentDigest = &d
		content = Content{ContentDigest: d, Tenant: trusted.Tenant, ActionID: trusted.ActionID, AdapterID: op.AdapterID, ContentBytes: b}
	}

	dataClass := trusted.WorkloadDataState.DataClassHighWater
	if dataClass == "" {
		dataClass = "none"
	}
	dataSources := append([]string{}, trusted.WorkloadDataState.DataSources...)

	env := ActionEnvelope{
		// SPEC-QUESTION: schema_version is taken from the catalog operation's
		// schema_version; TASK-02 does not name its source.
		SchemaVersion:      op.SchemaVersion,
		ActionID:           trusted.ActionID,
		RequestID:          trusted.RequestID,
		AuthenticatedActor: trusted.AuthenticatedActor,
		SessionKind:        trusted.SessionKind,
		SessionID:          trusted.SessionID,
		WorkloadID:         trusted.WorkloadID,
		EndpointID:         op.EndpointID,
		OperationID:        op.OperationID,
		CanonicalTarget:    res.canonical,
		Environment:        trusted.Environment,
		Tenant:             trusted.Tenant,
		DisclosureFields:   disclosure,
		DataClass:          dataClass,
		DataSources:        dataSources,
		ContentDigest:      contentDigest,
		ContentRef:         contentDigest, // content_ref is the action_contents key (content_digest)
		// SPEC-QUESTION: COMMON does not define "bytes"; here it is len(content_bytes), 0 without content.
		Bytes:                   int64(len(content.ContentBytes)),
		Limits:                  res.limits,
		CatalogDigest:           cat.CatalogDigest,
		CatalogVersion:          cat.CatalogVersion,
		CanonicalizationVersion: CanonicalizationVersion,
		RawBodyDigest:           RawBodyDigest(raw),
	}
	ad, err := ActionDigest(env.HashObject())
	if err != nil {
		return ActionEnvelope{}, Content{}, schemaErr(RuleSchema, "action_digest: %v", err)
	}
	env.ActionDigest = ad
	return env, content, nil
}

// SPEC-QUESTION: no reason code is defined for an invalid server-side context;
// CONTEXT_INCOMPLETE (403) is used and nothing is normalized.
func checkTrusted(t TrustedContext, cat Catalog) *NormalizeError {
	bad := func(msg string) *NormalizeError {
		return &NormalizeError{ReasonCodes: []string{ReasonContextIncomplete}, HTTPStatus: 403, Detail: msg}
	}
	switch {
	case t.ActionID == "" || t.RequestID == "" || t.AuthenticatedActor == "" || t.SessionID == "":
		return bad("action_id, request_id, authenticated_actor and session_id are required")
	case t.SessionKind != "user" && t.SessionKind != "service":
		return bad("session_kind must be user or service")
	case t.Tenant == "" || t.Environment == "":
		return bad("tenant and environment are required")
	case t.WorkloadDataState.DataClassHighWater != "" && !isDataClass(t.WorkloadDataState.DataClassHighWater):
		return bad("data_class_high_water is not a data_class")
	case cat.CatalogDigest == "":
		return bad("catalog has no catalog_digest")
	}
	return nil
}

func isDataClass(s string) bool { _, ok := dataClassRank[s]; return ok }

func decodeOp(raw json.RawMessage, v any, field string) *NormalizeError {
	if err := decodeStrict(raw, v); err != nil {
		return schemaErr(RuleSchema, "%s: %v", field, err)
	}
	return nil
}

// checkCatalogLimit enforces a catalog limits entry for a client-supplied value, if present.
func checkCatalogLimit(op CatalogOperation, name string, v int64) *NormalizeError {
	l, ok := op.Limits[name]
	if !ok {
		return nil
	}
	if (l.Min != nil && v < *l.Min) || v > l.Max {
		return schemaErr(RuleSchema, "%s outside catalog limits", name)
	}
	return nil
}

type targetLookup func(string) (CatalogTarget, *NormalizeError)

func normK8sList(a ClientAction, op CatalogOperation, lookup targetLookup) (opResult, *NormalizeError) {
	var t K8sListTarget
	var args K8sListArgs
	if e := decodeOp(a.RequestedTarget, &t, "requested_target"); e != nil {
		return opResult{}, e
	}
	if e := decodeOp(a.Arguments, &args, "arguments"); e != nil {
		return opResult{}, e
	}
	if err := validTargetID(t.TargetID); err != nil {
		return opResult{}, schemaErr(RuleSchema, "%v", err)
	}
	tg, e := lookup(t.TargetID)
	if e != nil {
		return opResult{}, e
	}
	ns, e := targetNamespace(tg)
	if e != nil {
		return opResult{}, e
	}
	return opResult{
		target:    tg,
		canonical: CanonicalTarget{Namespace: ns},
		limits:    map[string]int64{"limit": K8sListLimit, "response_bytes": K8sListResponseBytes},
	}, nil
}

// targetNamespace returns the fixed namespace of a Kubernetes target.
func targetNamespace(tg CatalogTarget) (string, *NormalizeError) {
	if tg.Namespace == nil || !isDNS1123Label(*tg.Namespace) {
		return "", notRegisteredErr("target %q has no valid namespace", tg.TargetID)
	}
	return *tg.Namespace, nil
}

func normK8sLogs(a ClientAction, op CatalogOperation, lookup targetLookup) (opResult, *NormalizeError) {
	var t K8sLogsTarget
	var args K8sLogsArgs
	if e := decodeOp(a.RequestedTarget, &t, "requested_target"); e != nil {
		return opResult{}, e
	}
	if e := decodeOp(a.Arguments, &args, "arguments"); e != nil {
		return opResult{}, e
	}
	if err := validateK8sLogs(t, args); err != nil {
		return opResult{}, schemaErr(RuleSchema, "%v", err)
	}
	if e := checkCatalogLimit(op, "tail_lines", args.TailLines); e != nil {
		return opResult{}, e
	}
	if e := checkCatalogLimit(op, "limit_bytes", args.LimitBytes); e != nil {
		return opResult{}, e
	}
	tg, e := lookup(t.TargetID)
	if e != nil {
		return opResult{}, e
	}
	ns, e := targetNamespace(tg)
	if e != nil {
		return opResult{}, e
	}
	return opResult{
		target:    tg,
		canonical: CanonicalTarget{Namespace: ns, PodName: t.PodName, Container: t.Container},
		limits:    map[string]int64{"tail_lines": args.TailLines, "limit_bytes": args.LimitBytes},
	}, nil
}

func normReceiver(a ClientAction, op CatalogOperation, lookup targetLookup) (opResult, *NormalizeError) {
	var t ReceiverTarget
	var args ReceiverArgs
	if e := decodeOp(a.RequestedTarget, &t, "requested_target"); e != nil {
		return opResult{}, e
	}
	if e := decodeOp(a.Arguments, &args, "arguments"); e != nil {
		return opResult{}, e
	}
	if err := validateReceiver(t, args); err != nil {
		return opResult{}, schemaErr(RuleSchema, "%v", err)
	}
	tg, e := lookup(t.TargetID)
	if e != nil {
		return opResult{}, e
	}
	if e := CheckReceiverContent(op, args.Payload); e != nil {
		return opResult{}, e
	}
	disclosure := []string{"summary"}
	if args.Payload.Email != nil {
		disclosure = append(disclosure, "email")
	}
	return opResult{
		target:       tg,
		limits:       map[string]int64{},
		disclosure:   disclosure,
		contentInput: args.Payload,
	}, nil
}

// modelContent is the content_digest input of model.generate (TASK-02 3.3).
type modelContent struct {
	Phase                  *string        `json:"phase,omitempty"`
	ConversationID         string         `json:"conversation_id"`
	Messages               []ModelMessage `json:"messages"`
	GenerationConfigDigest string         `json:"generation_config_digest"`
	ToolDeclarationsDigest string         `json:"tool_declarations_digest"`
	ResponseSchemaDigest   *string        `json:"response_schema_digest"`
}

func normModel(a ClientAction, op CatalogOperation, cat Catalog, lookup targetLookup) (opResult, *NormalizeError) {
	var t ModelTarget
	var args ModelArgs
	if e := decodeOp(a.RequestedTarget, &t, "requested_target"); e != nil {
		return opResult{}, e
	}
	if e := decodeOp(a.Arguments, &args, "arguments"); e != nil {
		return opResult{}, e
	}
	// Reject an explicitly present null phase on other profiles too.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(a.Arguments, &fields); err != nil {
		return opResult{}, schemaErr(RuleSchema, "invalid model arguments")
	}
	if _, present := fields["phase"]; present && t.Profile != "policy_proposal" {
		return opResult{}, schemaErr(RuleSchema, "profile %q does not allow phase", t.Profile)
	}
	if err := validateModel(t, args); err != nil {
		return opResult{}, schemaErr(RuleSchema, "%v", err)
	}
	tg, e := lookup(t.TargetID)
	if e != nil {
		return opResult{}, e
	}
	// SPEC-QUESTION: a profile missing from the operation's model_profiles, or
	// without server constants, is treated as not registered (403).
	if op.ModelProfiles == nil || !contains(*op.ModelProfiles, t.Profile) {
		return opResult{}, notRegisteredErr("profile %q is not registered for %s", t.Profile, op.OperationID)
	}
	pc, ok := cat.ModelProfiles[t.Profile]
	if !ok || len(pc.GenerationConfig) == 0 || pc.MaxOutputTokens <= 0 || pc.MaxRequestBytes <= 0 {
		return opResult{}, notRegisteredErr("profile %q has no server constants", t.Profile)
	}
	genDigest, err := CanonicalDigestJSON(pc.GenerationConfig)
	if err != nil {
		return opResult{}, notRegisteredErr("profile %q generation_config: %v", t.Profile, err)
	}
	var schemaDigest *string
	if len(pc.ResponseSchema) > 0 && string(pc.ResponseSchema) != "null" &&
		!(t.Profile == "policy_proposal" && args.Phase != nil && *args.Phase == "exploration") {
		d, err := CanonicalDigestJSON(pc.ResponseSchema)
		if err != nil {
			return opResult{}, notRegisteredErr("profile %q response_schema: %v", t.Profile, err)
		}
		schemaDigest = &d
	}
	tools := args.ToolDeclarations
	if tools == nil {
		tools = []ToolDeclaration{}
	}
	toolsDigest, err := CanonicalDigest(tools)
	if err != nil {
		return opResult{}, schemaErr(RuleSchema, "tool_declarations: %v", err)
	}
	var sources []string
	for _, m := range args.Messages {
		if (m.Kind == "text" || m.Kind == "tool_result") && m.Source != nil {
			sources = append(sources, *m.Source)
		}
	}
	return opResult{
		target:     tg,
		canonical:  CanonicalTarget{Profile: t.Profile},
		limits:     map[string]int64{"max_output_tokens": pc.MaxOutputTokens, "max_request_bytes": pc.MaxRequestBytes},
		disclosure: sources,
		contentInput: modelContent{
			Phase:                  args.Phase,
			ConversationID:         args.ConversationID,
			Messages:               args.Messages,
			GenerationConfigDigest: genDigest,
			ToolDeclarationsDigest: toolsDigest,
			ResponseSchemaDigest:   schemaDigest,
		},
	}, nil
}

func normEvidence(a ClientAction, op CatalogOperation, lookup targetLookup) (opResult, *NormalizeError) {
	var t EvidenceTarget
	var args EvidenceArgs
	if e := decodeOp(a.RequestedTarget, &t, "requested_target"); e != nil {
		return opResult{}, e
	}
	if e := decodeOp(a.Arguments, &args, "arguments"); e != nil {
		return opResult{}, e
	}
	if err := validateEvidence(t); err != nil {
		return opResult{}, schemaErr(RuleSchema, "%v", err)
	}
	tg, e := lookup(t.TargetID)
	if e != nil {
		return opResult{}, e
	}
	return opResult{
		target:    tg,
		canonical: CanonicalTarget{ResourceID: t.ResourceID},
		limits:    map[string]int64{"response_bytes": ReadResponseBytes},
	}, nil
}

func normDiscoverySource(a ClientAction, op CatalogOperation, lookup targetLookup) (opResult, *NormalizeError) {
	var t DiscoverySourceTarget
	var args DiscoverySourceArgs
	if e := decodeOp(a.RequestedTarget, &t, "requested_target"); e != nil {
		return opResult{}, e
	}
	if e := decodeOp(a.Arguments, &args, "arguments"); e != nil {
		return opResult{}, e
	}
	if err := validateDiscoverySource(t, args); err != nil {
		return opResult{}, schemaErr(RuleSchema, "%v", err)
	}
	for name, v := range map[string]int64{"start_line": args.StartLine, "end_line": args.EndLine} {
		if e := checkCatalogLimit(op, name, v); e != nil {
			return opResult{}, e
		}
	}
	tg, e := lookup(t.TargetID)
	if e != nil {
		return opResult{}, e
	}
	return opResult{
		target:    tg,
		canonical: CanonicalTarget{SnapshotID: t.SnapshotID, Path: t.Path},
		limits:    map[string]int64{"start_line": args.StartLine, "end_line": args.EndLine, "response_bytes": ReadResponseBytes},
	}, nil
}

func normDiscoveryCallgraph(a ClientAction, op CatalogOperation, lookup targetLookup) (opResult, *NormalizeError) {
	var t DiscoveryCallgraphTarget
	var args DiscoveryCallgraphArgs
	if e := decodeOp(a.RequestedTarget, &t, "requested_target"); e != nil {
		return opResult{}, e
	}
	if e := decodeOp(a.Arguments, &args, "arguments"); e != nil {
		return opResult{}, e
	}
	if err := validateDiscoveryCallgraph(t, args); err != nil {
		return opResult{}, schemaErr(RuleSchema, "%v", err)
	}
	if e := checkCatalogLimit(op, "depth", args.Depth); e != nil {
		return opResult{}, e
	}
	tg, e := lookup(t.TargetID)
	if e != nil {
		return opResult{}, e
	}
	return opResult{
		target:    tg,
		canonical: CanonicalTarget{SnapshotID: t.SnapshotID, Symbol: t.Symbol},
		limits:    map[string]int64{"depth": args.Depth, "response_bytes": ReadResponseBytes},
	}, nil
}

// NormalizeRaw is DecodeClientAction followed by Normalize.
func NormalizeRaw(raw []byte, trusted TrustedContext, cat Catalog) (ActionEnvelope, Content, *NormalizeError) {
	ca, err := DecodeClientAction(raw)
	if err != nil {
		return ActionEnvelope{}, Content{}, err
	}
	return Normalize(ca, raw, trusted, cat)
}
