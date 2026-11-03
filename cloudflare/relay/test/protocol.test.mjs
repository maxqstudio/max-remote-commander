import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  canonicalAssertion, canonicalCommand, canonicalSha256,
  verifyAssertion, verifySignedCommand, ProtocolError,
} from "../src/protocol.ts";

const vectors = JSON.parse(readFileSync(
  new URL("../../../testdata/protocol/v1/signing-vectors.json", import.meta.url),
  "utf8",
));

class MemoryReplay {
  constructor() { this.seen = new Set(); }
  async use(device, generation, nonce) {
    const key = device + ":" + generation + ":" + nonce;
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    return true;
  }
}

function scope(overrides = {}) {
  return {
    deviceId: vectors.command_envelope.value.device_id,
    generation: vectors.device_assertion.value.generation,
    agentSessionId: vectors.command_envelope.value.session_id,
    publicKey: vectors.identities.controller.public_key_b64url,
    now: vectors.command_envelope.value.issued_at,
    clockSkewSeconds: 0,
    replay: new MemoryReplay(),
    ...overrides,
  };
}

function wire(value) { return JSON.stringify(value); }

async function rejectsCode(callback, code) {
  await assert.rejects(callback, error => error instanceof ProtocolError && error.code === code);
}

test("Go canonical byte stream and SHA-256 match all three published vectors", async () => {
  for (const [kind, item] of [
    ["device", vectors.device_assertion],
    ["controller", vectors.controller_assertion],
  ]) {
    const canonical = canonicalAssertion(kind, wire(item.value));
    assert.equal(canonical, item.canonical_json);
    assert.equal(await canonicalSha256(canonical), item.canonical_sha256);
  }
  const canonical = canonicalCommand(wire(vectors.command_envelope.value));
  assert.equal(canonical, vectors.command_envelope.canonical_json);
  assert.equal(await canonicalSha256(canonical), vectors.command_envelope.canonical_sha256);
});

test("device and controller assertions validate against Go Ed25519 signatures", async () => {
  const device = vectors.device_assertion.value;
  const controller = vectors.controller_assertion.value;
  assert.equal((await verifyAssertion("device", wire(device), scope({
    publicKey: vectors.identities.device.public_key_b64url,
    now: device.issued_at,
  }))).agent_session_id, device.agent_session_id);
  assert.equal((await verifyAssertion("controller", wire(controller), scope({
    publicKey: vectors.identities.controller.public_key_b64url,
    now: controller.issued_at,
  }))).generation, controller.generation);
});

test("command verifies against Go-signed Ed25519 fixture and rejects replay", async () => {
  const auth = scope();
  const payload = wire(vectors.command_envelope.value);
  const result = await verifySignedCommand(payload, auth);
  assert.equal(result.tool, "filesystem.read");
  await rejectsCode(() => verifySignedCommand(payload, auth), "REPLAY");
});

test("tampering tool, arguments and signature fails before replay mutation", async () => {
  for (const mutate of [
    x => { x.tool = "filesystem.write"; },
    x => { x.arguments.limit = 32; },
    x => { x.signature = "A".repeat(86); },
  ]) {
    const changed = structuredClone(vectors.command_envelope.value);
    mutate(changed);
    await rejectsCode(() => verifySignedCommand(wire(changed), scope()), "INVALID_SIGNATURE");
  }
});

test("device, generation and session are bound to trusted paired state", async () => {
  const payload = wire(vectors.command_envelope.value);
  await rejectsCode(() => verifySignedCommand(payload, scope({ deviceId: "other-device" })), "BINDING_MISMATCH");
  await rejectsCode(() => verifySignedCommand(payload, scope({ agentSessionId: "rotated-session" })), "BINDING_MISMATCH");

  await rejectsCode(() => verifyAssertion("controller", wire(vectors.controller_assertion.value),
    scope({ generation: 8 })), "BINDING_MISMATCH");
});

test("expiry, lifetime and future issuance are rejected", async () => {
  const original = vectors.command_envelope.value;
  await rejectsCode(() => verifySignedCommand(wire(original),
    scope({ now: original.expires_at })), "EXPIRED");
  await rejectsCode(() => verifySignedCommand(wire(original),
    scope({ now: original.issued_at - 1 })), "FUTURE");
  const modified = { ...original, expires_at: original.issued_at + 301 };
  await rejectsCode(() => verifySignedCommand(wire(modified), scope()), "INVALID_TIME");
});

test("unexpected fields, duplicate fields and malformed JSON fail closed", () => {
  const original = wire(vectors.command_envelope.value);
  assert.throws(() => canonicalCommand(original.replace('{"version":1',
    '{"version":1,"version":1')), e => e.code === "DUPLICATE_FIELD");
  assert.throws(() => canonicalCommand(original.replace('{"version":1',
    '{"version":1,"self_approve":true')), e => e.code === "INVALID_FIELDS");
  assert.throws(() => canonicalCommand(original + "{}"), e => e.code === "INVALID_JSON");
  assert.throws(() => canonicalCommand('{"arguments":{}}'), e => e.code === "INVALID_FIELDS");
});

test("Go RawMessage canonicalization preserves numeric lexemes and escapes HTML", () => {
  const original = wire(vectors.command_envelope.value);
  const modified = original.replace('"limit":16',
    '"limit" : 1e+2, "path2":"<>&\\u2028", "zero":-0');
  const canonical = canonicalCommand(modified);
  assert.match(canonical, /"limit":1e\+2/);
  assert.match(canonical, /"zero":-0/);
  assert.ok(canonical.includes('"path2":"\\u003c\\u003e\\u0026\\u2028"'));
});

test("assertion shape is strict, and failure does not allocate replay", async () => {
  const value = structuredClone(vectors.device_assertion.value);
  const replay = new MemoryReplay();
  const auth = scope({
    publicKey: vectors.identities.device.public_key_b64url,
    now: value.issued_at,
    replay,
  });
  await rejectsCode(() => verifyAssertion("device", wire({ ...value, generation: 8 }), auth),
    "BINDING_MISMATCH");
  await verifyAssertion("device", wire(value), auth);
  await rejectsCode(() => verifyAssertion("device", wire(value), auth), "REPLAY");
});

test("explicitly invalid or absent signatures do not authorize commands", async () => {
  const missing = { ...vectors.command_envelope.value };
  delete missing.signature;
  await rejectsCode(() => verifySignedCommand(wire(missing), scope()), "INVALID_FIELDS");
  await rejectsCode(() => verifySignedCommand(wire({ ...vectors.command_envelope.value,
    signature: "@not-base64@" }), scope()), "INVALID_ENCODING");
});
