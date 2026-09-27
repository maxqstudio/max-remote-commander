# MAX Remote Commander

Secure, self-hosted, cross-platform remote computer agent gateway for LLM clients.

The accepted Phase 0 provides the protocol/security foundation. The Phase 1 candidate adds a bounded local capability executor. Automatic dispatch is deliberately read-only: filesystem mutation, process execution, and network clone require a trusted local approval mechanism that is not implemented yet; raw shell and unknown capabilities deny by default.

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
go build ./cmd/max-agent
```

Minimum Go version: 1.24.

Governance uses the STRICT profile and pinned Skill Workflow authority. Normal CI is read-only. Deterministic tracked governance output is synchronized only on dedicated `sync/**` branches and must then pass normal exact-SHA CI before acceptance.

## Support

- Saweria: https://saweria.co/maxq
- PayPal: https://paypal.me/JacksonJackson1501
