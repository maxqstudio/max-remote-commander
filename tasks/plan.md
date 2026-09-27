# Implementation Plan: MAX Remote Commander

## Overview
Build a secure, self-hosted, cross-platform remote computer agent gateway for LLM clients. The system uses structured capabilities, explicit local policy, outbound-only device networking, signed short-lived commands, replay protection, auditability, and optional privileged shell access behind approval.

## Architecture Decisions
- Go for agent/server binaries to keep distribution single-binary and cross-platform.
- Structured capabilities are the default contract; raw shell is privileged and never implicitly allowed.
- Device connections are outbound-only; no inbound listener is required on user PCs.
- Internal protocol is transport-neutral; initial relay may use HTTPS long-poll before WebSocket optimization.
- Skill_Workflow STRICT governance is pinned to exact upstream SHA 9e22feddb8f94e8c0f1af6a33e14b64de5068f8f.

## Task List

### Phase 0: Security and governance foundation
- [x] Bootstrap repository and funding links.
- [x] Define signed, expiring command envelope and replay protection.
- [x] Add workspace path guard including symlink escape defense.
- [ ] Add STRICT project-truth specs and deterministic governance validation.
- [ ] Add Linux/Windows/macOS GitHub Actions and prove PASS.

### Phase 1: Local capability executor
- [ ] Filesystem read/list/write/patch capabilities with policy checks.
- [ ] Process execution with argv-only safe default and timeouts.
- [ ] Git status/diff/clone capability layer.

### Phase 2: Remote relay
- [ ] Outbound device session registration and reconnect.
- [ ] Authenticated command queue and streamed result channel.
- [ ] Server-side device/session isolation.

### Phase 3: Pairing and identity
- [ ] Device Ed25519 identity and one-time pairing codes.
- [ ] Short-lived session tokens and revocation.
- [ ] Audit log with secret-safe event fields.

### Phase 4: Chat agent
- [ ] Provider-neutral LLM tool-call interface.
- [ ] Chat UI with device selector and approval prompts.
- [ ] OpenAI-compatible and local provider adapters.

### Phase 5: MCP and packaging
- [ ] MCP adapter over internal capability protocol.
- [ ] Cross-platform installers/service integration.
- [ ] Release artifacts and end-to-end acceptance.

## Risks and Mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| Prompt injection reaches shell | Critical | Structured capabilities by default; raw shell requires explicit policy/approval |
| Path traversal or symlink escape | Critical | Canonical workspace roots and deepest-existing-ancestor symlink validation |
| Captured command replay | High | Signed command envelope, nonce store, expiry, bounded lifetime |
| Compromised relay impersonates device | High | Device identity keys and signature verification at the agent |
| Cross-OS drift | High | GitHub Actions matrix on Linux, Windows, macOS for every accepted phase |

## Open Questions
None blocking Phase 0.
