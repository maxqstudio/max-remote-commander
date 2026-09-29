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
- Relay state remains in-memory until a later durability phase.
- Public relay deployment remains blocked until TLS configuration is implemented/proven.
- Skill_Workflow STRICT is pinned to 9e22feddb8f94e8c0f1af6a33e14b64de5068f8f.

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
- [ ] Synchronize deterministic Phase 3 Project Truth.
- [ ] Exact final Phase 3 5-job PASS and identical-SHA main revalidation.

### Phase 4: Chat agent and runnable client
- [ ] Outbound agent loop integrating identity/session/verifier/policy/approval/executor/audit.
- [ ] Provider-neutral LLM tool-call interface.
- [ ] Chat UI with device selector and local approval flow.
- [ ] OpenAI-compatible and local provider adapters.

### Phase 5: MCP, durability, TLS, packaging, E2E
- [ ] MCP adapter.
- [ ] Durable relay state/replay strategy.
- [ ] TLS/reverse-proxy deployment contract.
- [ ] Cross-platform installers/service integration and protected key storage hardening.
- [ ] Physical multi-OS end-to-end acceptance and release artifacts.

## Residual Risks
| Risk | Current control |
|---|---|
| Prompt injection reaches privileged execution | Remote request cannot grant approval; privileged operations require one-use local approval |
| Shared bootstrap key compromises paired devices | Bootstrap session issuance rejects already paired devices; paired sessions require device private key |
| Stale controller after agent restart | Controller session is bound to active agent session ID |
| Command replay | Relay command nonce guard plus agent verifier replay guard and per-start session binding |
| Relay restart data loss | Explicitly NOT_PROVEN/durable state deferred |
| Public plaintext exposure | Default loopback; public deployment blocked pending TLS |
| Windows seed protection | File-based identity is source-proven but OS-native protected storage/ACL hardening remains deferred |
