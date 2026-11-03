# Cloudflare Relay — P7 development

P7A verifies the Go protocol-v1 Ed25519 signing fixtures, canonical JSON, expiry, replay, and device/session bindings using Cloudflare-compatible WebCrypto.

P7B adds a **per-device SQLite state engine** in `src/state.ts` with transactional replay/queue commits, bounded FIFO leases, pairing generations/revocation, result durability, and fail-closed state rollback. Its SQL compatibility is currently tested using Node 24's real SQLite engine. The Cloudflare Durable Object adapter and Workerd integration tests are still pending.

## Tests

```sh
cd cloudflare/relay
npm test
```

There are no npm runtime dependencies for this checkpoint. Node 24 is required.

## Security boundary

The protocol verifier accepts raw signed command JSON so Go's `json.RawMessage` canonicalization is preserved. Signing validation is separated from replay insertion: a Worker/Durable Object must verify a paired public key and current agent-session binding **before** passing the verified command to the state engine; replay insertion and queue persistence then commit in one SQLite transaction.

`installVerifiedPairing`, `activateAuthenticatedAgentSession`, `commitVerifiedCommand`, `claimAssertionNonce`, and `revokeAuthenticatedDevice` are internal state operations, **not public endpoints**. Their caller must enforce pairing code, cryptographic assertion, active authorization, and session scope. Neither this module nor the network relay can authorize local privileged execution.

The frozen P7 sequence plan is `docs/sequence/plans/p7-cloudflare.plan.json`.

**NOT PROVEN:** Cloudflare Worker routing, Durable Object SQLite runtime behavior, WebSocket Hibernation, live short-lived bearer session issuance, public TLS deployment, free-tier resource budgets, MCP adapter, or physical E2E. No Cloudflare deployment is triggered by these GitHub commits.

## Cloudflare P7 runtime checkpoint

A Worker and a real SQLite-backed per-device Durable Object are wired in:
- Public router permits only device-scoped paths and /healthz.
- Per-device Durable Object enforces pairing, signed device/controller assertions,
  short-lived bearer sessions, atomic nonce + command insertion, FIFO lease,
  bounded result submission, and controller-owned result reads.
- Bootstrap enrolment is disabled without a >=32-character
  PAIRING_BOOTSTRAP_SECRET Cloudflare secret. Do not configure this as a
  repository variable or commit it; protect it as a restricted deployment
  secret and rotate it if exposed.
- Tests include Node protocol/SQLite vectors plus Workers runtime eviction
  and per-device SQLite isolation. Local worker tests do not require a
  live Cloudflare account.

Run the existing source tests with npm test, and the additional runtime
tests with npm install && npm run test:workerd. No deployment workflow
or secret is configured.

**P7 remains IN PROGRESS.** This is a source/runtime integration candidate,
not an approved production relay. Hibernation WebSocket, long poll,
Go transport compatibility, deployed Cloudflare staging E2E,
Free-tier billing evidence, and exact-SHA main acceptance remain pending.


The Vitest runner uses `wrangler.test.jsonc` and a clearly fake CI-only bootstrap
secret. The deployable `wrangler.jsonc` contains **no** bootstrap value, so
public pairing stays disabled unless a real secret is securely provisioned.
Do not deploy `wrangler.test.jsonc`.
