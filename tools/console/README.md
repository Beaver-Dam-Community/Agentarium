# Approval console

`tools/console` is the operator's local approval console for the M3-1 demo.
It runs on the operator's laptop, not in the cluster. While an agent action
waits in `approval_required`, the page shows it as a card in the session
timeline with the approval contract identity renders, and an Approve button.
After approval the card shows the approval and a Revoke button.

This console is a temporary M3-1 demo tool. The official approval UI is
`apps/console/approvals/` (TASK-03: React/TypeScript, browser OIDC
Authorization Code + PKCE, `max_age=300`, CSRF token), and it will replace
this console. Until then the console uses the CLI bearer ID token path that
TASK-03 allows for console users (the "CLI bearer ID token" paragraph, line
80), and it is the only approval surface in the M3-1 demo deployment. The
agent and the runtime are untrusted and never approve; nothing is added to
them or to the gateway.

## Usage

Reach identity through a port-forward, then start the console:

```sh
kubectl -n agent-control port-forward svc/workload-identity 18443:8443 &
go run ./tools/console -ca-file ca.pem
```

Start it from your own terminal only. Never start it through an agent
harness, a `!` command in an agent session, or any tool whose output an agent
can read: the printed URL contains the local API key, and a local process
that has it can forge `Origin` and approve as you through the loopback API.

It prints one URL, for example:

```
Approval console: http://127.0.0.1:53817/#k=Q2Vf...
```

Open that exact URL, including the `#k=` part. Enter a session ID and press
Watch, or use "Start a session" to create one (`POST /v1/sessions`). The page
polls pending approvals every 3 seconds. Each pending action appears as a
card with the operation, target, disclosure fields, content preview (exactly
as identity returns it), max actions, approval lifetime, environment, tenant,
contract digest and the intent check result. When the intent check is
`divergent` or `unclear`, every finding must be acknowledged before Approve
is enabled. After approval the runtime reevaluates every 15 seconds, so the
action proceeds within about 15 seconds.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-ca-file` | (required) | PEM trust bundle that verifies the identity server |
| `-identity-url` | `https://workload-identity.agent-control.svc:18443` | identity base URL |
| `-identity-dial` | `127.0.0.1:18443` | `host:port` dialed for the `-identity-url` host (the port-forward). Required: an empty value is rejected, because the `-identity-url` port is the port-forward port, not the Service port 8443 |
| `-identity-san` | `spiffe://agentarium.internal/ns/agent-control/sa/workload-identity` | exact URI SAN the identity certificate must carry |
| `-token-command` | `gcloud auth print-identity-token` | command printing a Google ID token on stdout, run without a shell. It is split on whitespace with `strings.Fields`, so quotes and escapes are not interpreted; wrap a command that needs them in a script |
| `-listen` | `127.0.0.1:0` | local address; must be a loopback IP (port 0 picks a free port) |

## Local API

The page calls only the console process, which proxies to identity:

| Local route | Identity route |
|---|---|
| `POST /api/sessions` | `POST /v1/sessions` |
| `GET /api/pending?session_id=` | `GET /v1/approvals/pending?session_id=` |
| `GET /api/actions/{action_id}/contract` | `GET /v1/actions/{action_id}/approval-contract` |
| `POST /api/approvals` | `POST /v1/approvals` |
| `POST /api/approvals/{approval_id}/revoke` | `POST /v1/approvals/{approval_id}/revoke` |

Request bodies are decoded strictly (unknown fields are rejected) and
re-encoded, IDs are checked as UUIDs, and only identity's status and JSON
body are relayed. The approve body carries `action_id`,
`displayed_contract_digest`, `nonce` and `acknowledged_findings`. The page
copies the digest and nonce verbatim from the contract response it
displayed; nothing is recomputed in the browser. Identity re-renders the
contract and compares the digest. `max_actions` is deliberately not sent:
identity sets it to 1 (TASK-03 3.1), and the console rejects a body that
carries it. Action and session IDs are forwarded in canonical UUID form.

The contract nonce is single use. Identity consumes it on every failed
approval except re-authentication, so after any other failure the card asks
for a contract reload. Loading a contract records a `contract_created` audit
event, so the page loads it once per card and again only on request or when
the action is pending again. When an action is listed as pending again after
its approval was revoked, or after it left the queue, its card loads a fresh
contract and nonce and offers Approve again; an old nonce is never reused.
When an unapproved action leaves the queue, its card drops the contract.

## Security notes

- **Identity TLS.** The identity certificate is verified against `-ca-file`
  and must carry exactly the `-identity-san` URI SAN. After chain
  verification the console applies `workloadcert.VerifyServiceLeaf`, which
  also rejects a CA certificate as the leaf and any DNS, IP or email SAN. The workload
  certificates have no DNS SAN, so Go's hostname check is replaced by this
  check; verification is never disabled. A wrong SAN or untrusted chain fails
  before any request, and therefore before the token, is sent.
- **ID token.** The console runs `-token-command` itself and keeps the token
  in memory until 2 minutes before `exp`. It is sent only to identity as
  `Authorization: Bearer`, and is never logged, written to disk or returned
  to the browser. Identity requires an approval token issued (`iat`) within
  5 minutes, so before an approval POST the console runs the command again
  if the cached token is older than 4 minutes. `gcloud` may itself return a
  cached token; if the new token is still older than 4 minutes, the console
  answers 503 `TOKEN_UNAVAILABLE` without calling identity, and the operator
  runs `gcloud auth login` and approves again. A 401 `AUTH_REQUIRED` from
  identity is handled the same way. Neither failure consumes the nonce.
  Concurrent requests share one run of the command, and a request whose
  cached token is still usable never waits for it. One run is bounded to
  30 seconds, inside the local server's 90 second write timeout.
- **Residual risk: the 5 minute check does not prove presence.** TASK-03
  (line 82) records this as a residual risk of the CLI demo path. Running the
  token command again gets a new `iat` from the stored refresh credential,
  without the operator signing in again, so a fresh `iat` shows only that the
  token is new, not that the operator is at the keyboard. It is not
  equivalent to the browser re-authentication (`max_age=300`) of
  `apps/console/approvals/`. The demo relies on the operator running the
  console in their own terminal and pressing Approve themselves.
- **Operator only.** The local key and loopback checks stop browsers and
  other origins, not local processes that saw the key. Run the console in
  your own terminal, outside any agent session.
- **Local listener.** `-listen` must be a loopback IP; `:port`, `0.0.0.0` and
  LAN addresses are refused. Every request must use a loopback `Host` on the
  listening port (DNS rebinding), a present `Origin` must equal
  `http://<Host>` and is required on POST (CSRF), and every `/api/` request
  must carry the per-process key in `X-Console-Key`. The key is random per
  process and printed once in the URL fragment, which browsers do not send
  to servers; the page moves it to `sessionStorage` and removes it from the
  address bar.
- **Page.** One embedded page with plain HTML, CSS and JavaScript, no external
  assets. Responses carry `Content-Security-Policy: default-src 'self'`,
  `frame-ancestors 'none'`, `nosniff` and `no-store`. Server strings are
  rendered with `textContent` only. The console does not add its own content
  preview; identity already withholds previews for internal and confidential
  data.

## Tests

```sh
go test ./tools/console/...
node --test tools/console/static/*.test.mjs
```

The page's pure decisions live in `static/logic.mjs`: which failed approval
keeps the nonce, and which cards to create, reopen or retire on each poll.
`static/logic.test.mjs` tests them with `node --test`; it is not embedded in
the binary.

The tests cover the listen, Host, Origin and key guards, the token cache
(one command run, refresh near `exp`, refresh before approval, stale token
refused, single-flight refresh, token absent from browser responses), strict
request forwarding with canonical IDs, and proxying to an `httptest` TLS
server with a test CA and URI SAN certificate, including the wrong SAN, two
URI SANs, missing ServerAuth EKU, untrusted CA, DNS-only, CA leaf and extra
DNS SAN certificate cases, and the rejection of an empty `-identity-dial`.
