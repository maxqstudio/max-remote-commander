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
- [x] Exact P5A branch-head f3a2ce567e50a2c0e8b96071a3253644b92d02da 5/5 PASS on run 36588006526
- [x] Fast-forward accepted P5A SHA f3a2ce567e50a2c0e8b96071a3253644b92d02da to main
- [x] Identical-SHA main revalidation 5/5 PASS on run 36588253106
- [x] Phase 5B canonical protocol + restart vectors source candidate 501cd78a2bfa06825471ae1a45ce64a5647d0807
- [x] Phase 5B Linux/Windows/macOS/race source lanes PASS on run 36589988772
- [ ] Phase 5B exact 5/5 work-branch governance acceptance
- [ ] Phase 5B identical-SHA main revalidation and P5 closure

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
