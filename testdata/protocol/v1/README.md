# Protocol v1 conformance vectors

These fixtures are the language-neutral compatibility boundary for future MAX Remote Commander transports and adapters.

- `signing-vectors.json` locks canonical JSON byte order, Ed25519 public keys, signatures, and SHA-256 digests for the device assertion, controller assertion, and command envelope.
- `restart-semantics.json` locks relay restart behavior for queued commands: an unexpired command may survive only when the reauthenticated agent session ID is unchanged; rotated-session or expired commands are pruned.
- The private seeds are deterministic **test-only** material published intentionally for reproducible signatures. They are not secrets and must never be used in production.
- Future Cloudflare, MCP, or other language implementations must consume these fixtures or equivalent generated test cases and produce the same results before they can claim protocol-v1 compatibility.

The Go tests are the current executable reference. A transport or adapter must not weaken device/generation/session binding to make a vector pass.
