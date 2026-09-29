# MAX Remote Commander

Secure, self-hosted, cross-platform remote computer agent gateway for LLM clients.

Current accepted main includes Phase 0-2. Phase 3 candidate adds persistent Ed25519 device identity, one-use device/controller pairing, Ed25519-authenticated device and controller sessions, active agent-session binding, controller-signed command envelopes, one-use local approval primitives, and bounded secret-safe audit logging.

The project is **not yet production-ready**: the runnable outbound agent/chat client, public TLS deployment, durable relay state, MCP adapter, OS-native key protection hardening, and physical-device end-to-end acceptance remain future phases.

## Project documentation

- [System overview](docs/SYSTEM_OVERVIEW.md)
- [Current state](docs/CURRENT_STATE.md)
- [Project manifest](docs/PROJECT_MANIFEST.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Acceptance matrix](docs/TEST_ACCEPTANCE_MATRIX.md)

## Development

```bash
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go build ./cmd/max-agent ./cmd/max-relay
```

Governance uses the STRICT profile and pinned Skill_Workflow authority.

## Support

- Saweria: https://saweria.co/maxq
- PayPal: https://paypal.me/JacksonJackson1501
