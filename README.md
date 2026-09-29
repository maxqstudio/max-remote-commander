# MAX Remote Commander

Secure, self-hosted, cross-platform remote computer agent gateway for LLM clients.

**Accepted source through Phase 3:** `95d60a599d2ea6ab75831c54bad5c999ab7d6901`.

The accepted core includes persistent Ed25519 device identity, one-use device/controller pairing, Ed25519-authenticated device and controller sessions, active agent-session binding, controller-signed command envelopes, bounded remote relay queues/results, one-use local approval primitives, bounded capability executors, and secret-safe audit logging primitives.

The project is **not yet production-ready**: the runnable outbound agent/chat client, user-facing local approval flow, audit runtime integration, public TLS deployment, durable relay state, MCP adapter, OS-native protected key storage hardening, and physical-device end-to-end acceptance remain future work.

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
