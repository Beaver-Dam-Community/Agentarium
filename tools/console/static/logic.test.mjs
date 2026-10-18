// Run with: node --test tools/console/static/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { nonceOutcome, reconcile } from "./logic.mjs";

test("nonce is kept only for re-authentication and local token failures", () => {
  assert.equal(nonceOutcome(401, ["AUTH_REQUIRED"]), "reauth");
  assert.equal(nonceOutcome(401, null), "reauth");
  assert.equal(nonceOutcome(503, ["TOKEN_UNAVAILABLE"]), "token");
  for (const [status, codes] of [
    [409, ["CONTRACT_DIGEST_MISMATCH"]],
    [403, ["APPROVAL_FORBIDDEN"]],
    [400, ["NONCE_INVALID"]],
    [502, ["IDENTITY_UNREACHABLE"]],
    [0, ["CONSOLE_UNREACHABLE"]],
    [500, null],
    [503, "TOKEN_UNAVAILABLE"], // not an array: not trusted
  ]) {
    assert.equal(nonceOutcome(status, codes), "consumed", status + " " + JSON.stringify(codes));
  }
});

const card = (o) => ({ gone: false, revoked: false, busy: false, ...o });

test("new pending actions get a card; missing ones leave", () => {
  const cards = new Map([["a", card()]]);
  assert.deepEqual(reconcile(cards, ["a", "b"]), { create: ["b"], reopen: [], leave: [] });
  assert.deepEqual(reconcile(cards, []), { create: [], reopen: [], leave: ["a"] });
});

test("an approved card still listed as pending is not reopened", () => {
  const cards = new Map([["a", card({ approval: { approval_id: "x" } })]]);
  assert.deepEqual(reconcile(cards, ["a"]), { create: [], reopen: [], leave: [] });
});

test("a revoked action that is still pending is reopened", () => {
  const cards = new Map([["a", card({ revoked: true })]]);
  assert.deepEqual(reconcile(cards, ["a"]), { create: [], reopen: ["a"], leave: [] });
});

test("an action that returns to pending after leaving is reopened, not duplicated", () => {
  const cards = new Map([["a", card()]]);
  let t = reconcile(cards, []);
  assert.deepEqual(t.leave, ["a"]);
  cards.get("a").gone = true;
  assert.deepEqual(reconcile(cards, []), { create: [], reopen: [], leave: [] });
  t = reconcile(cards, ["a"]);
  assert.deepEqual(t, { create: [], reopen: ["a"], leave: [] });
});

test("a card with a request in flight is not reopened", () => {
  const cards = new Map([["a", card({ revoked: true, busy: true })]]);
  assert.deepEqual(reconcile(cards, ["a"]).reopen, []);
});
