# MAX Remote Commander

Secure, self-hosted, cross-platform remote computer agent gateway for LLM clients.

Phase 0 and Phase 1 are accepted. The Phase 2 candidate adds an authenticated outbound relay: device reconnect rotates a short-lived session token, controller and registration bootstrap authorities are separate, command queues and completed results are bounded, devices long-poll outbound for work, and results are returned through controller-authenticated SSE.

Phase 2 relay state is still in-memory. The relay binds to `127.0.0.1:8787` by default and public TLS deployment is not yet proven. Final Ed25519 pairing, per-device controller identity, trusted local approval, and durable restart-safe state remain later phases.

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

Minimum Go version: 1.24.

## Relay development configuration

The relay refuses to start unless both secrets are at least 32 bytes and distinct:

```text
MAXRC_REGISTRATION_KEY=<secret>
MAXRC_CONTROLLER_KEY=<different-secret>
MAXRC_LISTEN=127.0.0.1:8787
```

Do not expose the Phase 2 HTTP listener directly to the public internet. TLS termination and production deployment are not yet part of accepted scope.

Governance uses the STRICT profile and pinned Skill Workflow authority. Normal CI is read-only. Deterministic tracked governance output is synchronized only on dedicated `sync/**` branches and must then pass normal exact-SHA CI before acceptance.

## Support

- Saweria: https://saweria.co/maxq
- PayPal: https://paypal.me/JacksonJackson1501
