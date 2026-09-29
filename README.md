# MAX Remote Commander

Secure, self-hosted, cross-platform remote computer agent gateway for LLM clients.

## Current project state

- **P6 Transport V2:** accepted and closed on `main` at exact source SHA `8e13e0374cee8724dd5dbda766a373f800d44afd`.
- **Next phase:** P7 Cloudflare Relay — Worker, Durable Objects, and WebSocket/Hibernation while preserving the existing protocol-v1 security boundary.
- **Not production-ready yet:** Cloudflare deployment, MCP gateway, desktop/web UX, protected OS-native key storage, packaging, scale/reliability, and physical end-to-end acceptance remain later roadmap phases.

The accepted security boundary remains: controller-signed structured commands are bound to the paired device and active agent session; the PC agent re-verifies them, applies local policy, requires trusted local approval for privileged capabilities, audits decisions, and executes only bounded capabilities. Raw shell is not a default capability.

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
