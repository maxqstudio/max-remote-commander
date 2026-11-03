import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {
  canonicalCommandEnvelope, canonicalControllerAssertion, canonicalDeviceAssertion,
  ProtocolError, verifyControllerAssertion, verifyDeviceAssertion, verifySignedCommand,
  type ReplayRecorder, type VerifyContext
} from "../src/protocol.ts";

const vectors = JSON.parse(await readFile(
  new URL("../../../testdata/protocol/v1/signing-vectors.json", import.meta.url), "utf8"));
const contexts: VerifyContext = {
  deviceID: "dev-vector-001",
  generation: 7,
  agentSessionID: "agent-session-vector-001",
  now: 1800000000,
  maxClockSkewSeconds: 30
};
function recorder(): ReplayRecorder {
  const recorded = new Set<string>();
  return {
    async recordOnce(kind, deviceID, generation, nonce, _expiresAt, _now) {
      const key = [kind, deviceID, generation, nonce].join(":");
      if (recorded.has(key)) return false;
      recorded.add(key);
      return true;
    }
  };
}
function commandRaw(value = vectors.command_envelope.value): string {
  return JSON.stringify(value);
}
async function sha256(payload: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function expectedCode(code: string) {
  return (error: unknown) => error instanceof ProtocolError && error.code === code;
}

test("device assertion canonical bytes, digest, Ed25519, and durable replay callback", async () => {
  const v = vectors.device_assertion;
  const canonical = canonicalDeviceAssertion(v.value);
  assert.equal(canonical, v.canonical_json);
  assert.equal(await sha256(canonical), v.canonical_sha256);
  const state = recorder();
  const publicKey = vectors.identities.device.public_key_b64url;
  await verifyDeviceAssertion(v.value, publicKey, contexts, state);
  await assert.rejects(verifyDeviceAssertion(v.value, publicKey, contexts, state), expectedCode("REPLAY"));
  await assert.rejects(verifyDeviceAssertion(v.value, publicKey,
    {...contexts, generation: 8}, recorder()), expectedCode("WRONG_BINDING"));
  await assert.rejects(verifyDeviceAssertion(v.value, publicKey,
    {...contexts, agentSessionID: "different"}, recorder()), expectedCode("WRONG_BINDING"));
  await assert.rejects(verifyDeviceAssertion({...v.value, nonce: "tampered"}, publicKey,
    contexts, recorder()), expectedCode("INVALID_SIGNATURE"));
});

test("controller assertion exact Go bytes/digest/signature and generation/expiry checks", async () => {
  const v = vectors.controller_assertion;
  const canonical = canonicalControllerAssertion(v.value);
  assert.equal(canonical, v.canonical_json);
  assert.equal(await sha256(canonical), v.canonical_sha256);
  const key = vectors.identities.controller.public_key_b64url;
  await verifyControllerAssertion(v.value, key, contexts, recorder());
  await assert.rejects(verifyControllerAssertion(v.value, key,
    {...contexts, generation: 6}, recorder()), expectedCode("WRONG_BINDING"));
  await assert.rejects(verifyControllerAssertion(v.value, key,
    {...contexts, now: v.value.expires_at}, recorder()), expectedCode("EXPIRED"));
});

test("command envelope exact Go bytes/digest/Ed25519 and replay", async () => {
  const v = vectors.command_envelope;
  assert.equal(canonicalCommandEnvelope(commandRaw()), v.canonical_json);
  assert.equal(await sha256(canonicalCommandEnvelope(commandRaw())), v.canonical_sha256);
  const key = vectors.identities.controller.public_key_b64url;
  const state = recorder();
  await verifySignedCommand(commandRaw(), key, contexts, state);
  await assert.rejects(verifySignedCommand(commandRaw(), key, contexts, state), expectedCode("REPLAY"));
  await assert.rejects(verifySignedCommand(commandRaw({...v.value, tool: "filesystem.write"}),
    key, contexts, recorder()), expectedCode("INVALID_SIGNATURE"));
  await assert.rejects(verifySignedCommand(commandRaw(), key,
    {...contexts, deviceID: "different"}, recorder()), expectedCode("WRONG_BINDING"));
  await assert.rejects(verifySignedCommand(commandRaw(), key,
    {...contexts, agentSessionID: "different"}, recorder()), expectedCode("WRONG_BINDING"));
  await assert.rejects(verifySignedCommand(commandRaw(), key,
    {...contexts, now: v.value.expires_at}, recorder()), expectedCode("EXPIRED"));
  await assert.rejects(verifySignedCommand(commandRaw(), key,
    {...contexts, now: v.value.issued_at - 31}, recorder()), expectedCode("FUTURE_ISSUED"));
});

test("strict parser rejects duplicate/unknown fields and unsafe numbers", async () => {
  const raw = commandRaw();
  const duplicate = raw.replace('"version":1', '"version":1,"version":1');
  assert.throws(() => canonicalCommandEnvelope(duplicate), expectedCode("INVALID_SHAPE"));
  assert.throws(() => canonicalCommandEnvelope(raw.replace('"version":1', '"version":1,"unexpected":true')),
    expectedCode("INVALID_SHAPE"));
  assert.throws(() => canonicalCommandEnvelope(raw.replace('"version":1', '"version":2')),
    expectedCode("INVALID_VERSION"));
  assert.throws(() => canonicalCommandEnvelope(raw.replace('"issued_at":1800000000',
    '"issued_at":9007199254740993')), expectedCode("INVALID_NUMBER"));
  await assert.rejects(verifySignedCommand(raw, vectors.identities.controller.public_key_b64url,
    contexts, undefined as unknown as ReplayRecorder), expectedCode("REPLAY_STORE_REQUIRED"));
});

test("canonical RawMessage preserves numeric-like key order and Go HTML escaping", () => {
  const raw = commandRaw().replace('"arguments":{"path":"workspace/file.txt","limit":16}',
    '"arguments": { "10": "a<&>", "2": "b", "value": "has spaces" }');
  const canonical = canonicalCommandEnvelope(raw);
  assert.ok(canonical.includes('"arguments":{"10":"a\\u003c\\u0026\\u003e","2":"b","value":"has spaces"}'));
  assert.ok(!canonical.includes('"arguments":{"2"'));
});
