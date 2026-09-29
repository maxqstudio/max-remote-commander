# MAX Remote Commander

Secure, self-hosted, cross-platform remote computer agent gateway for LLM clients.

## Current project state

- **P5 Protocol & Durability:** accepted and closed on `main`.
- **P6 Transport V2:** WebSocket command transport source is implemented and cross-platform tested; final acceptance is being revalidated under the latest pinned Skill_Workflow governance.
- **Not production-ready yet:** Cloudflare relay, MCP gateway, desktop/web UX, protected OS-native key storage, packaging, scale/reliability, and physical end-to-end acceptance remain later roadmap phases.

The security boundary is unchanged by transport work: controller-signed structured commands are bound to the paired device and active agent session; the PC agent re-verifies them, applies local policy, requires trusted local approval for privileged capabilities, audits decisions, and executes only bounded capabilities. Raw shell is not a default capability.

## Project documentation

- [System overview](docs/SYSTEM_OVERVIEW.md)
- [Current state](docs/CURRENT_STATE.md)
- [Roadmap](docs/ROADMAP.md)
- [Project manifest](docs/PROJECT_MANIFEST.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Acceptance matrix](docs/TEST_ACCEPTANCE_MATRIX.md)

`docs/ROADMAP.md` is generated. Roadmap authority is `.workflow/roadmap.json`.

## Development

```bash
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go build ./cmd/max-agent ./cmd/max-relay ./cmd/max-chat
```

Governance uses the STRICT profile and exact pinned Skill_Workflow authority recorded in `.workflow/authority.json`.

## Support

- Saweria: https://saweria.co/maxq
- PayPal: https://paypal.me/JacksonJackson1501
