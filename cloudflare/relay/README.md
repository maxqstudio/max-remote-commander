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
