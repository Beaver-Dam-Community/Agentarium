// Pure decisions of the approval page, kept free of the DOM so that
// logic.test.mjs can run them under node --test.

// nonceOutcome classifies a failed approve response. Identity consumes the
// contract nonce on every failure except re-authentication (401), and a
// local TOKEN_UNAVAILABLE never reached identity. "reauth" and "token" keep
// the nonce; "consumed" means the contract must be reloaded.
export function nonceOutcome(status, reasonCodes) {
  if (status === 401) return "reauth";
  if (Array.isArray(reasonCodes) && reasonCodes.includes("TOKEN_UNAVAILABLE")) return "token";
  return "consumed";
}

// reconcile compares the cards with the action IDs identity lists as
// pending. create: IDs without a card. reopen: cards that are pending again
// after they left the queue or their approval was revoked; each needs a fresh
// contract and nonce. leave: cards whose action is no longer pending. A card
// with a request in flight is left alone until it finishes.
export function reconcile(cards, pendingIds) {
  const pending = new Set(pendingIds);
  const out = { create: [], reopen: [], leave: [] };
  for (const id of pending) {
    const c = cards.get(id);
    if (!c) out.create.push(id);
    else if (!c.busy && (c.gone || c.revoked)) out.reopen.push(id);
  }
  for (const [id, c] of cards) {
    if (!pending.has(id) && !c.gone) out.leave.push(id);
  }
  return out;
}
