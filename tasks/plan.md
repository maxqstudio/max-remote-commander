# Implementation Plan: MAX Remote Commander

## Overview
Build a secure self-hosted cross-platform remote computer agent gateway for LLM clients, using structured capabilities, explicit local policy, outbound-only networking, signed short-lived commands, replay checks, and privileged operations behind trusted local approval.

## Architecture Decisions
- Go for single-binary cross-platform agent/server core.
- Go 1.24 minimum so filesystem execution uses traversal-resistant os.Root.
- Structured capabilities are default; raw shell is denied by default.
- Remote payloads cannot self-assert trusted approval.
- Device networking is outbound-only.
- Skill_Workflow STRICT is pinned to 9e22feddb8f94e8c0f1af6a33e14b64de5068f8f.

## Task List

### Phase 0: Security and governance foundation
- [x] Signed expiring command envelope and active-process replay rejection.
- [x] Workspace path guard.
- [x] STRICT Project Truth governance and Go-aware sequence validation.
- [x] Exact-SHA Linux/Windows/macOS/race/STRICT PASS and main revalidation.

### Phase 1: Local capability executor
- [x] os.Root filesystem read/list/write/patch with bounds.
- [x] Allowlisted argv-only process execution with trusted CWD, explicit environment, timeout, and output bounds.
- [x] Constrained Git status/diff/clone primitives.
- [x] Fail-closed default policy and automatic read-only dispatcher.
- [ ] Synchronize deterministic Phase 1 Project Truth.
- [ ] Exact final Phase 1 5-job PASS and identical-SHA main revalidation.

### Phase 2: Remote relay
- [ ] Outbound device registration/reconnect.
- [ ] Authenticated command queue and streamed result channel.
- [ ] Server-side device/session isolation.

### Phase 3: Pairing, trusted approval, and identity
- [ ] Device Ed25519 identity and one-time pairing codes.
- [ ] Trusted local approval binding for privileged capabilities.
- [ ] Short-lived session tokens, revocation, restart-safe replay strategy.
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
| Path traversal or symlink race | Critical | Go os.Root for actual filesystem operations |
| Arbitrary process execution | Critical | Explicit executable allowlist, argv-only, trusted CWD, bounded output/timeout |
| Unsafe Git behavior | High | no-ext-diff/no-textconv, HTTPS-only clone, no recursive submodules, clone hooks disabled |
| Replay after restart | High | Explicit open defect until durable state/per-start session strategy |
| Cross-OS drift | High | Linux/Windows/macOS matrix for every accepted phase |

## Open Questions
None blocking Phase 1 closure.
