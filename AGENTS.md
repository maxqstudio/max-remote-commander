# MAX Remote Commander — Agent operating contract

## Authorities and execution scope

- Read `PROJECT_PROFILE.yaml`, `.workflow/state.json`, `.workflow/roadmap.json`, generated `docs/CURRENT_STATE.md`, `docs/ROADMAP.md`, and the relevant source/test contracts before changing implementation.
- Project authority order: explicit Owner instructions and accepted acceptance criteria; project-specific contracts; specialized security/testing skills; pinned Skill_Workflow; general engineering guidance.
- `.workflow/*.json` owns semantic/governance truth; source owns implemented behavior; executed tests and runtime evidence own proof; generated `docs/*.md` is a deterministic projection, not an edit target.
- P0–P6 are accepted. P7 Cloudflare Relay is in progress. Do not mark P7 accepted until the exact required source, governance, Cloudflare runtime, resource-budget, and deployment evidence exists.
- Use governed work branches, smallest correct patches, and final exact-SHA acceptance. No unrelated refactoring or unrequested new capability.

## Execution environment

- This project is GitHub-first. Do not use the Owner's computer or local files for builds, tests, or changes without a separate explicit authorization.
- Use GitHub Actions as the execution and acceptance system. A successful earlier SHA does not authorize claiming a newer SHA is tested.
- No force push to `main`; promote only an independently accepted candidate, then revalidate `main`.
- A change in `state.json::phase` must accompany the corresponding change to `roadmap.json::current_phase`, with exactly one CURRENT roadmap phase.
- Fail-closed on missing test evidence; `NOT_PROVEN` cannot be promoted by documentation alone.
- Do not deploy to Cloudflare or expose public endpoints without explicit permitted account access and a proven security/deployment gate.

## Security invariants

- An LLM/MCP caller is not execution or approval authority. The MAX Agent's local policy, trusted local approval, bounded executor, and secret-safe audit remain the last security boundary.
- Command envelopes require paired Ed25519 authority, device/generation/agent-session binding, short expiry, and replay rejection.
- Cloudflare must conform to the accepted Go protocol-v1 test vectors; do not introduce a weaker Cloudflare-specific command protocol.
- Do not expose unrestricted shell/PowerShell/Bash/cmd as default MCP capabilities.
- The agent initiates outbound connections. Do not create an inbound PC command listener.
- Persist replay nonce and command enqueue atomically. Rejected writes must not consume valid nonces. Do not persist live bearer session tokens in durable relay snapshots.
- A WebSocket stream transports commands but does not authorize privilege. Command results must be acknowledged only after successful durable completion.
- Never commit actual credentials, device private keys, API keys, registration secrets, or production service tokens. Public protocol test seeds are test-only fixtures.

## Verification and handoff

- Before source changes: establish accepted base SHA, relevant workflow/sequence mode, security impact, and failing/targeted tests.
- After source changes: rerun targeted tests and cumulative Go Linux/Windows/macOS, race, TypeScript/SQLite, STRICT/Project Truth/sequence gates as applicable.
- Do not claim production/physical E2E from unit tests, emulator evidence, or GitHub runners.
- Document exact branch, SHA, Actions run IDs, PASS/FAIL lanes, known unproven boundaries, and next authorized action.
- When upgrading Skill_Workflow, use a fixed verified release SHA, migrate the toolchain/contract together, and prove the migration in Actions before treating the new pin as accepted.
