# Cloudflare Relay — P7 implementation

P7A establishes protocol-v1 cross-language conformance before any network endpoint is implemented.

`src/protocol.ts` verifies Ed25519 device assertions, controller assertions, and controller-signed command envelopes using Cloudflare-supported WebCrypto. It binds command authorization to a **trusted** paired-device public key and the **current** agent session ID. A caller must supply an atomic replay gate; no remote payload can assert local approval.

The verifier constructs the Go struct-field canonical order. Command arguments are taken from the raw JSON wire and compacted with Go `json.RawMessage` HTML escaping; it does not reserialize arguments through a JavaScript object.

Run with Node 24:

```sh
cd cloudflare/relay
node --experimental-strip-types --test test/protocol.test.mjs
```

These are protocol compatibility tests only. **No deployed Cloudflare Worker, Durable Object, SQLite persistence, session issuer, WebSocket endpoint, MCP gateway, or physical E2E is claimed.** A Durable Object must supply persisted pairings, generation, atomic replay checks, short-lived session authority and result durability before these functions may authorize network requests.

The frozen P7 sequence plan remains in `docs/sequence/plans/p7-cloudflare.plan.json`; subsequent implementation must conform to it without bypassing the Go agent's final local policy and approval checks.
