# MAX Remote Commander Tasks

## Accepted baseline

- [x] Phase 0 accepted/revalidated on main
- [x] Phase 1 accepted/revalidated on main at 6132e215fb15862471ec5a40acd72ca8d0422f88
- [x] Phase 2 accepted/revalidated on main at c0dfc797509c5afadd8f6cc847cdd45fb5ecf513
- [x] Phase 3 accepted/revalidated on main at 95d60a599d2ea6ab75831c54bad5c999ab7d6901
- [x] Phase 4 accepted/revalidated on main at 8c205dd1b1ee01fe3c73d44264493610a2704666

## P5 — Protocol & Durability

- [x] Phase 5A encrypted durable relay-state source
- [x] Phase 5A restart/replay/result/revoke/rollback regression tests
- [x] Phase 5A source candidate a0fc977588a12acd69b82cca1acff6c8884745a2 Linux/Windows/macOS/race PASS on run 36565884484
- [x] Skill_Workflow pin updated to 2148313678f476c4990e447b4d657724f071adff
- [x] Project Truth synchronization run 36566942745 reached 5/5 PASS at trigger SHA 752fc25d8d96e3f8d1f22ebe62ddb7bfdc11a271
- [ ] Obtain exact 5/5 PASS on the final P5A branch-head candidate
- [ ] Merge accepted P5A candidate to main
- [ ] Revalidate accepted P5A state on main
- [ ] Freeze/document canonical restart semantics and protocol test vectors for P5 closure

## Forward roadmap

- [ ] P6 Transport V2 — WebSocket, reconnect, heartbeat, session rebinding
- [ ] P7 Cloudflare Relay — Worker, Durable Objects, WebSocket/Hibernation
- [ ] P8 MCP Gateway — structured capability adapter, no default unrestricted shell
- [ ] P9 Multi-client Compatibility — ChatGPT-compatible, Codex/IDE, generic MCP conformance
- [ ] P10 Device & Permission Model — multi-device, scopes, revoke, per-device policy
- [ ] P11 Desktop Agent UX — pairing/status/local approval/audit UI
- [ ] P12 Web Dashboard — device/session/audit/revocation management
- [ ] P13 ChatGPT Integration — supported ChatGPT app/plugin surface over MCP
- [ ] P14 Extended Capabilities — bounded filesystem/Git/process/app/screen capabilities
- [ ] P15 Security Hardening — threat model, fuzzing, injection/replay/downgrade/secret review
- [ ] P16 Packaging — Windows/Linux/macOS installers, services, protected key storage
- [ ] P17 Scale & Reliability — load, reconnect/offline, recovery, retention, resource budgets
- [ ] P18 Physical E2E — real internet/devices/relay/MCP/restart/approval evidence
- [ ] P19 Public Release — docs, onboarding, artifacts, security process, v1.0.0

See `docs/ROADMAP.md` for phase boundaries and exit gates.
