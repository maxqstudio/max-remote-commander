# Implementation Plan: MAX Remote Commander

## Overview
Build a secure self-hosted cross-platform remote computer agent gateway for LLM clients using paired cryptographic identities, outbound-only networking, signed short-lived commands, local policy, one-use local approvals, bounded execution, and secret-safe audit metadata.

## Architecture Decisions
- Go 1.24 for single-binary cross-platform core and traversal-resistant os.Root.
- Structured capabilities are default; raw shell remains denied by default.
- Initial shared registration key is pre-pairing bootstrap only and has no controller command authority.
- Paired device and controller sessions require Ed25519 proof-of-possession.
- Controller sessions and signed commands are bound to the active per-start agent session ID.
- Remote payloads cannot self-assert trusted local approval.
- Configured relay restart-critical state is stored in a bounded AES-256-GCM snapshot; bearer sessions and transient pairing/lease state remain ephemeral.
- Public relay deployment remains blocked until TLS configuration is implemented/proven.
- Skill_Workflow STRICT is pinned to 2148313678f476c4990e447b4d657724f071adff.

## Task List

### Phase 0: Security and governance foundation
- [x] Accepted and revalidated on main.

### Phase 1: Local capability executor
- [x] Accepted and revalidated on main at 6132e215fb15862471ec5a40acd72ca8d0422f88.

### Phase 2: Remote relay
- [x] Accepted and revalidated on main at c0dfc797509c5afadd8f6cc847cdd45fb5ecf513.

### Phase 3: Pairing, trusted approval, and identity
- [x] Persistent Ed25519 device identity and deterministic device ID.
- [x] One-use high-entropy pairing codes with generation/revocation.
- [x] Ed25519-authenticated paired device sessions.
- [x] Ed25519-authenticated paired controller sessions.
- [x] Controller and command authority bound to active agent session.
- [x] Relay-side signed CommandEnvelope validation and nonce replay rejection.
- [x] One-use exact-request local approval grants.
- [x] Bounded secret-safe audit primitive.
- [x] Synchronize deterministic Phase 3 Project Truth.
- [x] Exact source SHA 95d60a599d2ea6ab75831c54bad5c999ab7d6901 5-job PASS on work branch and identical-SHA main revalidation.

### Phase 4: Runnable agent and terminal chat integration
- [x] Outbound agent loop integrating identity/session/verifier/policy/approval/executor/audit.
- [x] Provider-neutral bounded LLM tool-call interface.
- [x] Interactive trusted local terminal approval flow with default deny.
- [x] Paired controller bridge with active-agent-session refresh.
- [x] OpenAI-compatible and loopback-local provider adapter.
- [x] Cross-platform `max-chat` terminal client.
- [x] Exact Phase 4 STRICT governance acceptance and main revalidation at 8c205dd1b1ee01fe3c73d44264493610a2704666.

Phase 4 scope decision: graphical multi-device chat UI/device selector moves to Phase 5; it is not claimed as implemented.

### Phase 5A: Encrypted relay durability
- [x] AES-256-GCM bounded versioned state snapshot with externally supplied 32-byte key.
- [x] Persist pairing trust/generations, queue/request/result state, and unexpired replay guards.
- [x] Keep bearer sessions, leases, pairing offers, and pairing receipts ephemeral across restart.
- [x] Roll back durable in-memory mutations when persistence fails.
- [x] Revoke old-generation durable queue/result/replay state.
- [x] Prove Store recreation, replay rejection, stale-session pruning, result restoration, and rollback across Linux/Windows/macOS/race.
- [x] Exact Phase 5A SHA f3a2ce567e50a2c0e8b96071a3253644b92d02da passed work run 36588006526 and identical-SHA main run 36588253106.

### Phase 5B: Canonical protocol and restart vectors
- [ ] Freeze deterministic protocol/restart test vectors shared by future transports and adapters.
- [ ] Prove stale-session, expiry, replay, signature, generation, and capability-envelope conformance without weakening session binding.
- [ ] Close P5 Protocol & Durability only after exact work/main acceptance.

### P6-P19 production roadmap
- [ ] P6 Transport V2 — WebSocket reconnect, heartbeat, bounded backoff, and session rebinding.
- [ ] P7 Cloudflare Relay — Worker, Durable Objects, and WebSocket/Hibernation.
- [ ] P8 MCP Gateway — structured capability adapter with no default unrestricted shell.
- [ ] P9 Multi-client Compatibility.
- [ ] P10 Device & Permission Model.
- [ ] P11 Desktop Agent UX.
- [ ] P12 Web Dashboard.
- [ ] P13 ChatGPT Integration.
- [ ] P14 Extended Capabilities.
- [ ] P15 Security Hardening.
- [ ] P16 Packaging.
- [ ] P17 Scale & Reliability.
- [ ] P18 Physical E2E.
- [ ] P19 Public Release.

See `docs/ROADMAP.md` for phase boundaries and exit gates.

## Residual Risks
| Risk | Current control |
|---|---|
| Prompt injection reaches privileged execution | Remote request cannot grant approval; privileged operations require one-use local approval |
| Shared bootstrap key compromises paired devices | Bootstrap session issuance rejects already paired devices; paired sessions require device private key |
| Stale controller after agent restart | Controller session is bound to active agent session ID |
| Command replay | Relay command nonce guard plus agent verifier replay guard and per-start session binding |
| Relay restart data loss | Configured encrypted snapshot is source/CI-proven across Store recreation; physical deployed crash/power-loss recovery remains NOT_PROVEN |
| Public plaintext exposure | Default loopback; public deployment blocked pending TLS |
| Windows seed protection | File-based identity is source-proven but OS-native protected storage/ACL hardening remains deferred |
