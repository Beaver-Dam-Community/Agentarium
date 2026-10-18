# policies/gateway/decision.rego — gateway decision (TASK-04 3.2, COMMON policy decision contract).
#
# Rego v1. The gateway prepares data.agentarium.gateway.result from the signed
# bundle and evaluates it with the OPA input of TASK-04 3.2. Every rule has a
# stable rule_id; result = {verdict, reason_codes, matched_rule_ids,
# evaluated_rule_ids, decision_basis}.
#
# Data shapes follow COMMON Appendix A: data.standing_rules is a map keyed by
# standing_rule_id with operation_ids[], and data.service_profiles[profile] is
# {operation_ids[], model_profiles[], target_ids[]}.
package agentarium.gateway

required_keys := {"envelope", "verified_session", "approval_snapshot", "workload_data_state", "control_health"}

missing_keys contains k if {
	some k in required_keys
	not k in object.keys(input)
}

env := input.envelope

sess := input.verified_session

now := time.parse_rfc3339_ns(input.control_health.evaluated_at)

target := data.catalog.targets[env.canonical_target.target_id]

operation := data.catalog.operations[env.operation_id]

disclosure_operations := {"receiver.submit", "model.generate"}

versioned_components := {"adapter"}

# ---------- denials: {code, rule_id} ----------

denials contains {"code": "CONTEXT_INCOMPLETE", "rule_id": "input.required_keys.v1"} if {
	count(missing_keys) > 0
}

denials contains {"code": "CONTEXT_INCOMPLETE", "rule_id": "input.evaluated_at.v1"} if {
	not now
}

endpoint_registered if {
	operation.endpoint_id == target.endpoint_id
	env.operation_id in target.operation_ids
	env.canonical_target.route_id == operation.route_id
}

denials contains {"code": "ENDPOINT_NOT_REGISTERED", "rule_id": "catalog.endpoint_registered.v1"} if {
	not endpoint_registered
}

denials contains {"code": "CATALOG_DIGEST_MISMATCH", "rule_id": "catalog.digest_match.v1"} if {
	not env.catalog_digest == data.catalog.catalog_digest
}

session_valid if {
	sess.kind == "user"
	sess.state == "claimed"
	env.session_kind == "user"
	sess.session_id == env.session_id
	sess.authenticated_actor == env.authenticated_actor
	sess.workload_id == env.workload_id
	sess.tenant == env.tenant
	time.parse_rfc3339_ns(sess.expires_at) > now
}

session_valid if {
	sess.kind == "service"
	sess.state == "active"
	env.session_kind == "service"
	sess.session_id == env.session_id
	sess.authenticated_actor == env.authenticated_actor
	sess.tenant == env.tenant
	time.parse_rfc3339_ns(sess.expires_at) > now
}

denials contains {"code": "SESSION_BINDING_INVALID", "rule_id": "session.binding.v1"} if {
	not session_valid
}

target_env_ok if {
	target.environment == env.environment
	target.tenant == env.tenant
}

denials contains {"code": "TARGET_SCOPE_DENIED", "rule_id": "target.scope.v1"} if {
	endpoint_registered
	not target_env_ok
}

denials contains {"code": "TARGET_SCOPE_DENIED", "rule_id": "target.scope.v1"} if {
	sess.kind == "user"
	not env.operation_id in sess.allowed_operation_ids
}

denials contains {"code": "DISCLOSURE_SCOPE_DENIED", "rule_id": "disclosure.receiver.v1"} if {
	env.operation_id == "receiver.submit"
	some f in env.disclosure_fields
	not f in data.receiver.allowed_disclosure_fields
}

data_class_allowed if {
	data.data_class_rank[input.workload_data_state.data_class_high_water] <= data.data_class_rank[target.max_data_class]
}

denials contains {"code": "DATA_CLASS_DENIED", "rule_id": "data_class.high_water.v1"} if {
	env.operation_id in disclosure_operations
	not data_class_allowed
}

# ---------- service session scope ----------

service_scope_ok if {
	sess.kind == "service"
	p := data.service_profiles[sess.service_scope.profile]
	env.operation_id in p.operation_ids
	env.canonical_target.target_id in p.target_ids
	model_profile_ok(p)
	scope_binding_ok
}

# model.generate must use one of the profile's model profiles; other
# operations carry no model profile.
model_profile_ok(_) if env.operation_id != "model.generate"

model_profile_ok(p) if {
	env.operation_id == "model.generate"
	env.canonical_target.profile in p.model_profiles
}

scope_binding_ok if not startswith(env.operation_id, "discovery.")

scope_binding_ok if {
	startswith(env.operation_id, "discovery.")
	env.canonical_target.snapshot_id == sess.service_scope.snapshot_id
}

denials contains {"code": "SERVICE_SCOPE_DENIED", "rule_id": "service.scope_allow.v1"} if {
	sess.kind == "service"
	not service_scope_ok
	not standing_rule_id
}

# ---------- approval contract (user sessions) ----------

# ApprovalContract is a single-action user approval (TASK-03). A service
# session never carries one; if it does, the request is denied rather than
# recorded as decision_basis = approval.
approval_present if input.approval_snapshot != null

has_approval if {
	sess.kind == "user"
	approval_present
}

denials contains {"code": "APPROVAL_INVALID", "rule_id": "approval.binding.v1"} if {
	sess.kind == "service"
	approval_present
}

approval_matches if {
	a := input.approval_snapshot
	a.approval_kind == "action"
	a.session_id == env.session_id
	a.authenticated_actor == env.authenticated_actor
	a.allowed_operation == env.operation_id
	a.canonical_target == env.canonical_target
	a.disclosure_fields == env.disclosure_fields
	a.content_digest == env.content_digest
}

approval_usable if {
	a := input.approval_snapshot
	a.revoked_at == null
	a.used_actions < a.max_actions
	time.parse_rfc3339_ns(a.expires_at) > now
}

denials contains {"code": "APPROVAL_INVALID", "rule_id": "approval.binding.v1"} if {
	has_approval
	not approval_matches
}

denials contains {"code": "APPROVAL_UNAVAILABLE", "rule_id": "approval.usable.v1"} if {
	has_approval
	approval_matches
	not approval_usable
}

# ---------- standing rules (only without an approval) ----------

matched_standing contains r.standing_rule_id if {
	not has_approval
	some id, r in data.standing_rules
	r.standing_rule_id == id
	r.session_kind == sess.kind
	env.operation_id in r.operation_ids
	glob.match(r.target_pattern, ["/"], env.canonical_target.target_id)
	standing_profile_ok(r)
	every k, v in env.limits {
		v <= r.limits[k]
	}
	standing_disclosure_ok(r)
	standing_data_ok(r)
}

# profile is null for rules that apply to any profile (standing.k8s_read.v1).
# `not r.profile` would fail on null, so compare with null explicitly.
standing_profile_ok(r) if object.get(r, "profile", null) == null

standing_profile_ok(r) if {
	r.session_kind == "user"
	env.canonical_target.profile == r.profile
}

standing_profile_ok(r) if {
	r.session_kind == "service"
	sess.service_scope.profile == r.profile
	sess.service_scope.change_id != null
}

standing_disclosure_ok(r) if object.get(r, "disclosure_fields", null) == null

standing_disclosure_ok(r) if {
	every f in env.disclosure_fields {
		f in r.disclosure_fields
	}
}

standing_data_ok(r) if object.get(r, "data_profile", null) == null

standing_data_ok(r) if {
	data.data_class_rank[input.workload_data_state.data_class_high_water] <= data.data_class_rank[r.data_profile]
}

standing_rule_id := sort(matched_standing)[0]

# ---------- holds and required leases ----------

probe_exempt(h) if {
	h.reason == "policy_activation"
	standing_rule_id == "probe.activation.v1"
	p := input.control_health.activation_probe
	p.service_session_id == sess.session_id
	p.change_id == sess.service_scope.change_id
	p.action_id == env.action_id
	time.parse_rfc3339_ns(p.expires_at) > now
}

denials contains {"code": "HOLD_ACTIVE", "rule_id": "hold.blocking.v1"} if {
	some h in input.control_health.active_holds
	not probe_exempt(h)
}

probe_exempt_ids contains "hold.activation_probe_exempt.v1" if {
	some h in input.control_health.active_holds
	probe_exempt(h)
}

denials contains {"code": "CONTROL_HEALTH_UNAVAILABLE", "rule_id": "health.required_leases.v1"} if {
	count(object.get(input.control_health, "required_leases", [])) == 0
}

denials contains {"code": "CONTROL_HEALTH_UNAVAILABLE", "rule_id": "health.required_leases.v1"} if {
	some l in input.control_health.required_leases
	not lease_ok(l)
}

lease_ok(l) if {
	l.observed_state != "unhealthy"
	time.parse_rfc3339_ns(l.lease_until) > now
	not l.component in versioned_components
}

lease_ok(l) if {
	l.observed_state != "unhealthy"
	time.parse_rfc3339_ns(l.lease_until) > now
	l.component in versioned_components
	l.active_version == input.control_health.active_artifact_digest
}

# ---------- evaluated rules ----------

evaluated contains id if {
	some id in {
		"input.required_keys.v1", "input.evaluated_at.v1", "catalog.endpoint_registered.v1",
		"catalog.digest_match.v1", "session.binding.v1", "target.scope.v1",
		"hold.blocking.v1", "health.required_leases.v1",
	}
}

evaluated contains "disclosure.receiver.v1" if env.operation_id == "receiver.submit"

evaluated contains "data_class.high_water.v1" if env.operation_id in disclosure_operations

evaluated contains "service.scope_allow.v1" if sess.kind == "service"

evaluated contains "approval.binding.v1" if approval_present

evaluated contains "approval.usable.v1" if has_approval

evaluated contains r.standing_rule_id if {
	some r in data.standing_rules
	r.session_kind == sess.kind
	env.operation_id in r.operation_ids
}

evaluated contains "hold.activation_probe_exempt.v1" if count(object.get(input.control_health, "active_holds", [])) > 0

# ---------- result ----------

deny_codes := {d.code | some d in denials}

deny_rule_ids := {d.rule_id | some d in denials}

verdict := "deny" if {
	count(denials) > 0
} else := "allow" if {
	sess.kind == "user"
	approval_matches
	approval_usable
} else := "allow" if {
	standing_rule_id
} else := "allow" if {
	service_scope_ok
} else := "approval_required" if {
	sess.kind == "user"
} else := "deny"

reason_codes := sort(deny_codes) if {
	count(denials) > 0
} else := ["APPROVAL_REQUIRED"] if {
	verdict == "approval_required"
} else := ["SERVICE_SCOPE_DENIED"] if {
	verdict == "deny"
} else := []

decision_basis := "approval" if {
	verdict == "allow"
	has_approval
} else := "activation_probe" if {
	verdict == "allow"
	standing_rule_id == "probe.activation.v1"
} else := "standing_rule" if {
	verdict == "allow"
	standing_rule_id
} else := "service_scope" if {
	verdict == "allow"
	service_scope_ok
} else := null

matched_rule_ids := sort(deny_rule_ids) if {
	count(denials) > 0
} else := array.concat(["approval.allow.v1"], sort(probe_exempt_ids)) if {
	decision_basis == "approval"
} else := array.concat([standing_rule_id], sort(probe_exempt_ids)) if {
	decision_basis in {"standing_rule", "activation_probe"}
} else := ["service.scope_allow.v1"] if {
	decision_basis == "service_scope"
} else := ["approval.required_default.v1"] if {
	verdict == "approval_required"
} else := ["service.scope_allow.v1"]

result := {
	"verdict": verdict,
	"reason_codes": reason_codes,
	"matched_rule_ids": matched_rule_ids,
	"evaluated_rule_ids": sort(evaluated),
	"decision_basis": decision_basis,
}
