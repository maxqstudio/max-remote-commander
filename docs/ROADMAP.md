# MAX Remote Commander Roadmap

This document is the forward product roadmap for MAX Remote Commander.

It is planning authority for phase order and product boundaries. Current acceptance truth remains in `.workflow/state.json`, generated Project Truth documents, and exact GitHub Actions evidence. A roadmap entry is not proof that a feature exists.

## Product direction

MAX Remote Commander is a secure remote-computer execution backend for AI clients.

The security core is independent of any single LLM or client:

```text
AI / MCP client
    |
    v
MCP / client adapter
    |
    v
MAX Remote Commander capability protocol
    |
    +------------------------+
    |                        |
    v                        v
Cloudflare relay       Self-hosted Go relay
    |                        |
    +-----------+------------+
                |
               WSS
                |
                v
             MAX Agent
                |
        Policy -> Approval -> Audit
                |
                v
         Bounded executor
```

### Locked architectural rules

- MCP is a northbound adapter, not the security authority.
- The PC agent remains the final execution authority.
- Privileged actions require trusted local approval unless a narrower local policy explicitly allows them.
- Remote input cannot self-assert approval.
- The agent uses outbound connectivity; normal operation does not require an inbound PC port.
- Structured capabilities are the default interface.
- Unrestricted shell, PowerShell, Bash, and cmd execution are not normal MCP capabilities and remain default-denied.
- The same capability/security protocol must support both Cloudflare and self-hosted relay modes.
- ChatGPT is one client integration, not the architecture root.
- Security/session binding must not be weakened to preserve queued work across restart.

## Completed foundation

| Phase | Status | Scope |
|---|---|---|
| P0 | CLOSED | Initial governed project baseline |
| P1 | CLOSED | Core protocol and identity foundation |
| P2 | CLOSED | Relay/controller trust and policy foundation |
| P3 | CLOSED | Bounded executor, local approval, audit, and cross-platform security regression |
| P4 | CLOSED | Runnable outbound agent, controller bridge, provider-neutral chat loop, OpenAI-compatible adapter, and max-chat |

## Production roadmap

| Phase | Focus | Exit gate |
|---|---|---|
| **P5 — Protocol & Durability** | Finish encrypted relay durability, restart semantics, replay protection, canonical protocol/test vectors, and fail-closed recovery rules. | Exact work-branch 5/5 CI PASS, merge to main, identical-SHA/main revalidation, durability semantics documented without weakening session binding. |
| **P6 — Transport V2** | Add WebSocket transport alongside/after long-poll with reconnect, heartbeat, bounded backoff, and session rebinding. | Cross-OS tests prove reconnect and stale-session rejection; no inbound PC listener. |
| **P7 — Cloudflare Relay** | Add Cloudflare Worker + Durable Object relay path, WebSocket/Hibernation transport, and durable routing/state appropriate to Cloudflare. | Deployed test environment routes paired traffic without opening the PC to inbound internet traffic; shared protocol vectors PASS. |
| **P8 — MCP Gateway** | Implement a remote MCP adapter over the existing structured capability protocol. | MCP discovery/calls map only to declared capabilities; unknown/unrestricted shell calls fail closed. |
| **P9 — Multi-client Compatibility** | Validate one backend contract with ChatGPT-compatible MCP flows, Codex/IDE clients, and generic MCP clients where supported. | No protocol fork per client; shared conformance suite PASS. |
| **P10 — Device & Permission Model** | Multi-device naming, selection, revocation, capability scopes, and per-device approval policy. | Device A/B isolation, revocation, and scope tests PASS. |
| **P11 — Desktop Agent UX** | Add desktop/tray experience for pairing, connection status, approvals, and audit visibility. | Normal user operation no longer requires terminal interaction; privilege boundary remains local. |
| **P12 — Web Dashboard** | Device/session/audit/revocation administration UI. | Dashboard cannot bypass agent policy; management flows have E2E tests. |
| **P13 — ChatGPT Integration** | Package the MCP-backed integration for the current supported ChatGPT app/plugin surface without making OpenAI-specific behavior part of the core. | ChatGPT -> MCP -> relay -> agent -> result E2E proven on a supported account/workspace surface. |
| **P14 — Extended Capabilities** | Expand bounded filesystem, Git, process, app-launch, and optional screen/GUI capabilities. | Every new capability has explicit schema, bounds, policy, approval class, audit shape, and adversarial tests. |
| **P15 — Security Hardening** | Threat-model refresh, fuzzing, prompt/tool injection tests, replay/downgrade tests, secret handling, and dependency review. | Security review and adversarial suite PASS with no unresolved release-blocking findings. |
| **P16 — Packaging** | Windows/Linux/macOS installers, service integration, protected key storage, and update strategy. | Fresh-machine install/uninstall/service lifecycle PASS on all three OS families. |
| **P17 — Scale & Reliability** | Load limits, reconnect/offline behavior, queue/result retention, state recovery, and free-tier/resource budgeting. | Published limits and repeatable reliability/load tests PASS for Cloudflare and self-hosted modes. |
| **P18 — Physical E2E** | Real internet, real devices, Cloudflare/self-hosted relay, MCP clients, restart/recovery, and approval flows. | Physical evidence PASS across the supported production matrix. |
| **P19 — Public Release** | Final docs, onboarding, release artifacts, security disclosure process, and versioned production release. | `v1.0.0` release artifacts and final main validation PASS. |

## Current execution checkpoint

Current implementation work is **P5 / Phase 5A encrypted relay durability** on `work/phase-5a-durability`.

P5 is not complete until the exact accepted source has passed all blocking CI lanes on the work branch, is merged to `main`, and the accepted main state is revalidated. GitHub-hosted restart tests do not by themselves prove physical crash or power-loss recovery.

Queued commands remain bound to an agent session. If a relay/agent restart produces a new agent session, stale-session queued commands must be rejected or pruned rather than replayed under a different session.

## MCP V1 capability boundary

Initial MCP exposure is planned around structured capabilities such as:

```text
device.list
device.status

filesystem.list
filesystem.read
filesystem.write
filesystem.patch

git.status
git.diff
git.clone

process.run

audit.latest
```

The MCP adapter must not expose these as ordinary/default tools:

```text
shell.exec
powershell.exec
bash.exec
cmd.exec
```

If raw-shell capability is ever introduced, it requires a separate explicit high-risk design, default-off policy, strict local authorization, and dedicated adversarial acceptance.

## Supported deployment direction

### Cloud mode

```text
AI client -> MCP gateway -> Cloudflare Worker / Durable Object -> WSS -> MAX Agent
```

Target: low-operations deployment with outbound-only device connectivity.

### Self-hosted mode

```text
AI client -> MCP gateway -> Go relay -> WSS -> MAX Agent
```

Target: developer, homelab, enterprise, and privacy-controlled deployments.

Both modes must preserve the same signed capability protocol, identity rules, policy semantics, approval boundary, and audit contract.

## Phase workflow

Every implementation phase follows:

```text
inspect current authority
-> work branch
-> smallest correct implementation
-> tests and adversarial checks
-> GitHub Actions blocking lanes PASS
-> merge to main
-> revalidate main
-> record exact evidence
-> next phase
```

No future phase is treated as complete from roadmap text alone.
