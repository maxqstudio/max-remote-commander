# Implementation Plan: MAX Remote Commander

## Overview
Build a secure self-hosted cross-platform remote computer agent gateway for LLM clients, using structured capabilities, explicit local policy, outbound-only networking, signed short-lived commands, replay checks, and privileged operations behind trusted local approval.

## Architecture Decisions
- Go for single-binary cross-platform agent/server core.
- Go 1.24 minimum so filesystem execution uses traversal-resistant os.Root.
- Structured capabilities are default; raw shell is denied by default.
- Remote payloads cannot self-assert trusted approval.
- Device networking is outbound-only; Phase 2 uses long-poll for commands and SSE for controller results.
- Relay state is deliberately in-memory in Phase 2; durability and final device identity remain later work.
- Skill_Workflow STRICT is pinned to 9e22feddb8f94e8c0f1af6a33e14b64de5068f8f.

## Task List

### Phase 0: Security and governance foundation
- [x] Accepted and revalidated on main.

### Phase 1: Local capability executor
- [x] os.Root filesystem read/list/write/patch with bounds.
- [x] Allowlisted argv-only process execution.
- [x] Constrained Git primitives.
- [x] Fail-closed automatic read-only dispatcher.
- [x] Exact final 5-job PASS and main revalidation at 6132e215fb15862471ec5a40acd72ca8d0422f88.

### Phase 2: Remote relay
- [x] Authenticated outbound device registration/reconnect with session rotation.
- [x] Bounded authenticated command queue with leases.
- [x] Device/session isolation and owning-device result checks.
- [x] Controller-authenticated SSE result channel.
- [x] Bounded completed-result retention.
- [ ] Synchronize deterministic Phase 2 Project Truth.
- [ ] Exact final Phase 2 5-job PASS and identical-SHA main revalidation.

### Phase 3: Pairing, trusted approval, and identity
- [ ] Device Ed25519 identity and one-time pairing codes.
- [ ] Trusted local approval binding for privileged capabilities.
- [ ] Short-lived paired controller tokens, revocation, restart-safe replay strategy.
- [ ] Secret-safe audit log.

### Phase 4: Chat agent
- [ ] Provider-neutral LLM tool-call interface.
- [ ] Chat UI with device selector and approval prompts.
- [ ] OpenAI-compatible and local provider adapters.

### Phase 5: MCP and packaging
- [ ] MCP adapter.
- [ ] Cross-platform installers/service integration.
- [ ] Release artifacts and end-to-end acceptance.

## Risks and Mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| Prompt injection reaches privileged execution | Critical | Remote request cannot grant approval; privileged tools stop at local approval boundary |
| Cross-device command/result mix-up | Critical | Session token is bound to device ID; request ownership checked on result |
| Relay memory DoS | High | Per-device queue and completed-result retention are bounded |
| Bootstrap secret compromise | High | Registration/controller authorities are distinct; Phase 3 replaces bootstrap identity with pairing |
| Relay restart data loss | High | Explicit Phase 2 limitation; durability not claimed |
| Public plaintext relay exposure | Critical | Default loopback bind; public TLS deployment remains blocked/unproven |
| Cross-OS drift | High | Linux/Windows/macOS matrix for every accepted phase |

## Open Questions
None blocking Phase 2 closure.
