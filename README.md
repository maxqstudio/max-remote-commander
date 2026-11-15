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


## Experimental human-operated remote access (issue #2)

The `max-connect` CLI is a **separate human-operated LAN/VPN client**, not an LLM tool or a session over MAX Remote Commander's relay. It requires a user-provisioned SSH/SFTP server or compatible Windows RDP host. It does not install those services, configure a VPN, or expose remote ports.

```bash
go build ./cmd/max-connect
max-connect check --host dev.lan --user developer
max-connect terminal --host dev.lan --user developer
max-connect files --host dev.lan --user developer
# On Windows only, with a supported RDP host:
max-connect desktop --host dev.lan
```

For non-default SSH ports or keys, add `--port 2222 --identity /path/to/key --known-hosts /path/to/known_hosts` after the mode. `check` performs a non-interactive SSH authentication check with a fixed `exit 0` command; it does not verify that the remote computer is suitable for a build.

**Host trust:** SSH/SFTP uses `StrictHostKeyChecking=yes` and disables per-user SSH config. Verify the host fingerprint through a trusted separate channel and enroll it using an ordinary SSH client before first use; unknown or changed keys are rejected. Never blindly trust `ssh-keyscan` output from an untrusted network.

**Limitations:** Windows desktop mode launches `mstsc.exe`, not an embedded desktop stream. Windows Home is not a built-in RDP server. Other desktop clients and Android UI are deferred. RDP authentication/certificate validation belongs to the native OS client. This is an experimental CLI, **not** a production-ready remote-access application. The P7 WebSocket blocker remains independent and unresolved.
