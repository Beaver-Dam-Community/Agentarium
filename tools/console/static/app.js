// Approval console page. Every server string is rendered with textContent;
// nothing is parsed as HTML. The contract digest and nonce sent on approve
// are copied verbatim from the contract response that is displayed.
import { nonceOutcome, reconcile } from "./logic.mjs";

const POLL_MS = 3000;
const REEVALUATE_S = 15;

const key = (() => {
  const m = /(?:^#|&)k=([A-Za-z0-9_-]+)/.exec(location.hash);
  if (m) {
    sessionStorage.setItem("console-key", m[1]);
    history.replaceState(null, "", location.pathname);
  }
  return sessionStorage.getItem("console-key") || "";
})();

const $ = (id) => document.getElementById(id);
const cards = new Map(); // action_id -> card state
let sessionId = "";
let pollTimer = 0;

function el(tag, opts, ...children) {
  const n = document.createElement(tag);
  if (opts) {
    if (opts.cls) n.className = opts.cls;
    if (opts.text !== undefined) n.textContent = String(opts.text);
    if (opts.type) n.type = opts.type;
  }
  for (const c of children) if (c) n.append(c);
  return n;
}

async function api(method, path, body) {
  const init = { method, headers: { "X-Console-Key": key }, cache: "no-store" };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch (e) {
    return { status: 0, data: { reason_codes: ["CONSOLE_UNREACHABLE"] } };
  }
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  return { status: res.status, data };
}

function reasons(r) {
  const codes = r.data && Array.isArray(r.data.reason_codes) ? r.data.reason_codes.join(", ") : "";
  return "HTTP " + r.status + (codes ? " " + codes : "");
}

function stamp() {
  return el("time", { text: new Date().toLocaleTimeString() });
}

function addEvent(text, cls) {
  const li = el("li", { cls: cls || "" }, stamp(), el("span", { text }));
  $("timeline").append(li);
  return li;
}

function field(dl, name, value, mono) {
  dl.append(el("dt", { text: name }));
  const dd = el("dd", { cls: mono ? "mono" : "" });
  if (value instanceof Node) dd.append(value); else dd.textContent = value === undefined || value === null ? "" : String(value);
  dl.append(dd);
}

// ---- session ------------------------------------------------------------------

function watch(id) {
  sessionId = id.trim();
  $("session-id").value = sessionId;
  addEvent("Watching session " + sessionId);
  clearTimeout(pollTimer);
  poll();
}

async function poll() {
  if (!sessionId) return;
  const r = await api("GET", "/api/pending?session_id=" + encodeURIComponent(sessionId));
  if (r.status === 200 && r.data && Array.isArray(r.data.actions)) {
    $("poll-status").textContent = "Last checked " + new Date().toLocaleTimeString() + ", " + r.data.actions.length + " pending";
    $("poll-status").className = "muted";
    const byId = new Map();
    for (const a of r.data.actions) {
      if (a && typeof a.action_id === "string") byId.set(a.action_id, a);
    }
    const t = reconcile(cards, byId.keys());
    for (const id of t.create) newCard(byId.get(id));
    for (const id of t.reopen) reopen(cards.get(id));
    for (const id of t.leave) leave(cards.get(id));
  } else {
    $("poll-status").textContent = "Pending check failed: " + reasons(r);
    $("poll-status").className = "error";
  }
  pollTimer = setTimeout(poll, POLL_MS);
}

// ---- cards ----------------------------------------------------------------------

function leave(c) {
  c.gone = true;
  c.li.classList.add("gone");
  c.state.textContent = c.approval
    ? "No longer waiting for approval: the runtime reevaluated the action."
    : "No longer waiting for approval.";
  c.state.className = "status muted";
  if (!c.approval) {
    // The contract nonce is not reused if the action comes back.
    c.contract = null;
    c.buttons.replaceChildren();
  }
  addEvent("Action " + c.id + " left the approval queue");
}

// reopen makes a card actionable again when its action is pending again
// (after a revoke or after it left the queue). The old nonce is either used
// up or belongs to an older contract, so a fresh contract is always loaded.
function reopen(c) {
  c.gone = false;
  c.revoked = false;
  c.approval = null;
  c.contract = null;
  c.li.classList.remove("gone", "approved");
  addEvent("Action " + c.id + " is waiting for approval again");
  loadContract(c);
}

function newCard(p) {
  const c = { id: p.action_id, pending: p, contract: null, approval: null, gone: false, revoked: false, busy: false };
  c.body = el("div");
  c.state = el("p", { cls: "status" });
  c.buttons = el("div", { cls: "actions" });
  const box = el("div", { cls: "card-box" },
    el("h3", { text: "Approval required: " + (p.operation_id || "") }),
    c.body, c.state, c.buttons);
  c.li = el("li", { cls: "card" }, stamp(), el("span", { text: "Action " + p.action_id + " is waiting for approval" }), box);
  $("timeline").append(c.li);
  cards.set(p.action_id, c);
  loadContract(c);
}

async function loadContract(c) {
  c.state.textContent = "Loading approval contract…";
  c.state.className = "status muted";
  c.buttons.replaceChildren();
  const r = await api("GET", "/api/actions/" + encodeURIComponent(c.id) + "/contract");
  if (r.status !== 200 || !r.data || !r.data.contract || typeof r.data.contract_digest !== "string" || typeof r.data.nonce !== "string") {
    c.contract = null;
    c.body.replaceChildren();
    c.state.textContent = "Could not load the approval contract: " + reasons(r);
    c.state.className = "status error";
    c.buttons.replaceChildren(button("Reload contract", () => loadContract(c), true));
    return;
  }
  c.contract = r.data;
  renderContract(c);
}

function button(label, onClick, secondary) {
  const b = el("button", { text: label, cls: secondary ? "secondary" : "", type: "button" });
  b.addEventListener("click", onClick);
  return b;
}

const KNOWN = new Set(["contract_version", "action_id", "operation_id", "operation_label", "target",
  "disclosure_fields", "content_preview", "max_actions", "expires_in_seconds", "environment", "tenant"]);

function renderContract(c) {
  const ct = c.contract.contract;
  const dl = el("dl");
  field(dl, "Operation", (ct.operation_label || "") + " (" + (ct.operation_id || "") + ")");
  const t = ct.target || {};
  field(dl, "Target", (t.label || "") + " (" + (t.target_id || "") + ")");
  field(dl, "Disclosure fields", Array.isArray(ct.disclosure_fields) ? ct.disclosure_fields.join(", ") : "");
  if (ct.content_preview) {
    const cp = ct.content_preview;
    field(dl, "Content preview", el("pre", { cls: "preview", text: cp.text === undefined ? "" : cp.text }));
    field(dl, "Preview truncated", cp.truncated ? "yes" : "no");
    field(dl, "Content digest", cp.content_digest, true);
  } else {
    field(dl, "Content", "This action sends no content.");
  }
  field(dl, "Max actions", ct.max_actions);
  field(dl, "Approval lifetime", ct.expires_in_seconds + " s after approval");
  field(dl, "Environment", ct.environment);
  field(dl, "Tenant", ct.tenant);
  field(dl, "Action ID", ct.action_id, true);
  field(dl, "Contract version", ct.contract_version);
  field(dl, "Contract digest", c.contract.contract_digest, true);
  for (const k of Object.keys(ct)) {
    if (!KNOWN.has(k)) field(dl, k, JSON.stringify(ct[k]), true);
  }

  const ic = c.contract.intent_check || {};
  c.invalid = "";
  const required = [];
  const checks = [];
  let intent;
  if (ic.intent_check_status === "completed" && (ic.overall === "divergent" || ic.overall === "unclear")) {
    intent = el("div", { cls: "findings" }, el("strong", { cls: "warn", text: "Intent check: " + ic.overall + ". Acknowledge every finding to approve." }));
    for (const f of Array.isArray(ic.findings) ? ic.findings : []) {
      if (!f || typeof f.finding_id !== "string" || f.finding_id === "") {
        c.invalid = "Identity returned an intent check finding without a finding_id, so it cannot be acknowledged. Reload the contract; do not approve.";
        continue;
      }
      required.push(f.finding_id);
      const cb = el("input", { type: "checkbox" });
      cb.addEventListener("change", () => updateApprove(c));
      checks.push(cb);
      const span = typeof f.user_text_span === "string" ? f.user_text_span : JSON.stringify(f.user_text_span);
      intent.append(el("label", null, cb, el("span", {
        text: "[" + (f.severity || "") + "] " + (f.kind || "") + " at " + (f.contract_path || "") +
          ": " + (f.explanation || "") + (span && span !== "null" ? " (user text: " + span + ")" : ""),
      })));
    }
  } else if (ic.intent_check_status === "completed") {
    intent = el("p", { cls: "muted", text: "Intent check: " + (ic.overall || "") + ". It grants nothing; review the contract above." });
  } else {
    intent = el("p", { cls: "muted", text: "Intent check not run" + (ic.not_run_reason ? ": " + ic.not_run_reason : "") + ". Approve on the contract above alone." });
  }
  c.required = required;
  c.checks = checks;
  c.body.replaceChildren(dl, intent);
  c.state.textContent = c.invalid || "Waiting for your decision. The contract nonce is single use and expires 10 minutes after loading.";
  c.state.className = c.invalid ? "status error" : "status muted";
  c.approveBtn = button("Approve", () => approve(c));
  c.buttons.replaceChildren(c.approveBtn, button("Reload contract", () => loadContract(c), true));
  updateApprove(c);
}

function updateApprove(c) {
  if (c.approveBtn) c.approveBtn.disabled = c.busy || Boolean(c.invalid) || !c.checks.every((cb) => cb.checked);
}

async function approve(c) {
  if (!c.contract || c.busy || c.invalid) return;
  c.busy = true;
  updateApprove(c);
  c.state.textContent = "Approving…";
  c.state.className = "status muted";
  const r = await api("POST", "/api/approvals", {
    action_id: c.id,
    displayed_contract_digest: c.contract.contract_digest,
    nonce: c.contract.nonce,
    acknowledged_findings: c.required,
  });
  c.busy = false;
  if (r.status === 200 && r.data && typeof r.data.approval_id === "string") {
    c.approval = r.data;
    c.contract = null; // the nonce is used up
    c.li.classList.add("approved");
    addEvent("Approved action " + c.id + " (approval " + r.data.approval_id + ", revision " + r.data.revision + ")");
    renderApproved(c);
    return;
  }
  const outcome = nonceOutcome(r.status, r.data && r.data.reason_codes);
  c.state.textContent = "Approval failed: " + reasons(r) + (outcome === "reauth"
    ? ". Identity needs an ID token issued within 5 minutes; refresh it (gcloud auth login) and approve again."
    : outcome === "token" ? ". The console could not get a fresh ID token; check its terminal (run gcloud auth login if the token is too old) and approve again."
      : ". The nonce is used up; reload the contract before approving again.");
  c.state.className = "status error";
  if (outcome !== "consumed") {
    updateApprove(c);
  } else {
    c.contract = null;
    c.buttons.replaceChildren(button("Reload contract", () => loadContract(c), true));
  }
}

function renderApproved(c) {
  const a = c.approval;
  const dl = el("dl");
  field(dl, "Approval ID", a.approval_id, true);
  field(dl, "Revision", a.revision);
  field(dl, "Policy epoch", a.policy_epoch);
  field(dl, "Contract digest", a.contract_digest, true);
  const exp = new Date(a.expires_at);
  field(dl, "Expires at", isNaN(exp) ? String(a.expires_at) : exp.toLocaleTimeString());
  c.body.append(dl);
  c.state.textContent = "Approved. The runtime reevaluates every " + REEVALUATE_S + " s, so the action should proceed within about " + REEVALUATE_S + " s.";
  c.state.className = "status ok";
  c.buttons.replaceChildren(button("Revoke", () => revoke(c), true));
}

async function revoke(c) {
  if (!c.approval || c.busy) return;
  c.busy = true;
  const r = await api("POST", "/api/approvals/" + encodeURIComponent(c.approval.approval_id) + "/revoke");
  c.busy = false;
  if (r.status === 200 && r.data) {
    c.li.classList.remove("approved");
    c.revoked = true;
    c.state.textContent = "Revoked (" + (r.data.revoke_reason || "") + "). If the runtime already used the approval, the action is not undone. " +
      "If the action is still pending, a fresh contract loads here for a new decision.";
    c.state.className = "status warn";
    c.buttons.replaceChildren();
    addEvent("Revoked approval " + c.approval.approval_id);
    return;
  }
  c.state.textContent = "Revoke failed: " + reasons(r);
  c.state.className = "status error";
}

// ---- forms --------------------------------------------------------------------

function list(v) {
  return v.split(",").map((s) => s.trim()).filter(Boolean);
}

document.addEventListener("DOMContentLoaded", () => {
  if (!key) $("key-missing").hidden = false;
  $("watch-form").addEventListener("submit", (e) => {
    e.preventDefault();
    watch($("session-id").value);
  });
  $("create-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const r = await api("POST", "/api/sessions", {
      workload_id: $("workload-id").value.trim(),
      task_statement: $("task-statement").value,
      requested_scope: { operation_ids: list($("operation-ids").value), target_ids: list($("target-ids").value) },
    });
    if ((r.status === 200 || r.status === 201) && r.data && typeof r.data.session_id === "string") {
      addEvent("Session " + r.data.session_id + " created, expires " + new Date(r.data.expires_at).toLocaleTimeString() +
        ". The runtime claims it through assignments.");
      watch(r.data.session_id);
    } else {
      addEvent("Session create failed: " + reasons(r), "error");
    }
  });
});
