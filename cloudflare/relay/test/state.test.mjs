import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPrivateKey, sign } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { DurableRelayState, DurableStateError } from "../src/state.ts";
import { canonicalCommand, verifySignedCommandSignature } from "../src/protocol.ts";

const vectors = JSON.parse(readFileSync(
  new URL("../../../testdata/protocol/v1/signing-vectors.json", import.meta.url), "utf8",
));
const fixture = vectors.command_envelope.value;
const deviceKey = vectors.identities.device.public_key_b64url;
const controllerKey = vectors.identities.controller.public_key_b64url;
const generation = vectors.device_assertion.value.generation;
const deviceId = fixture.device_id;
const now = fixture.issued_at;
const pkcs8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  Buffer.from(vectors.identities.controller.seed_b64url, "base64url"),
]);
const testPrivateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });

function database(t) {
  const directory = mkdtempSync(join(tmpdir(), "maxrc-sqlite-"));
  const path = join(directory, "relay.sqlite");
  const openHandles = [];
  t.after(() => {
    for (const handle of openHandles) handle.close();
    rmSync(directory, { recursive: true, force: true });
  });
  return () => {
    const db = new DatabaseSync(path);
    openHandles.push(db);
    return {
      sql: {
        exec(sql, ...params) {
          const statement = db.prepare(sql);
          if (/^\s*SELECT\b/i.test(sql)) return statement.all(...params);
          statement.run(...params);
          return [];
        },
      },
      transactionSync(callback) {
        db.exec("BEGIN IMMEDIATE");
        try {
          const result = callback();
          db.exec("COMMIT");
          return result;
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
      },
    };
  };
}

function paired(store) {
  const trust = store.installVerifiedPairing(deviceId, deviceKey, controllerKey);
  assert.equal(trust.generation, 1);
  return trust;
}

function activate(store, generationValue = 1, sessionId = fixture.session_id, nonce = "device-auth-1") {
  store.activateAuthenticatedAgentSession(deviceId, generationValue, sessionId, nonce,
    now + 30, now);
}

async function signedInput(requestId, nonce, sessionId = fixture.session_id) {
  const value = { ...fixture, request_id: requestId, nonce, session_id: sessionId, signature: "" };
  const signingBytes = canonicalCommand(JSON.stringify(value));
  value.signature = sign(null, Buffer.from(signingBytes), testPrivateKey).toString("base64url");
  const envelopeJSON = JSON.stringify(value);
  const verified = await verifySignedCommandSignature(envelopeJSON, {
    deviceId,
    generation: 1,
    agentSessionId: sessionId,
    publicKey: controllerKey,
    now,
    clockSkewSeconds: 0,
  });
  return {
    requestId: verified.request_id,
    deviceId: verified.device_id,
    generation: 1,
    agentSessionId: verified.session_id,
    nonce: verified.nonce,
    issuedAt: verified.issued_at,
    expiresAt: verified.expires_at,
    envelopeJSON,
  };
}

function code(error, expected) {
  return error instanceof DurableStateError && error.code === expected;
}

test("pairing trust, replay and results survive SQLite-backed state recreation", async t => {
  const open = database(t);
  const first = new DurableRelayState(open());
  paired(first);
  activate(first);
  const command = await signedInput("req-durable-1", "nonce-durable-1");
  first.commitVerifiedCommand(command, now);

  const second = new DurableRelayState(open());
  assert.equal(second.pairing().deviceId, deviceId);
  assert.throws(() => second.leaseHead(deviceId, 1, fixture.session_id, now, 10),
    err => code(err, "SESSION_MISMATCH"));
  activate(second, 1, fixture.session_id, "device-auth-2");

  const head = second.leaseHead(deviceId, 1, fixture.session_id, now, 10);
  assert.equal(head.requestId, command.requestId);
  assert.equal(head.envelopeJSON, command.envelopeJSON);
  second.completeResult(deviceId, 1, fixture.session_id, command.requestId,
    '{"status":"completed"}', now);
  const third = new DurableRelayState(open());
  assert.equal(third.resultForAuthorizedController(deviceId, 1, command.requestId, now).payload,
    '{"status":"completed"}');
  assert.throws(() => second.commitVerifiedCommand(command, now), err => code(err, "REPLAY"));
});

test("session rotation prunes previous queue and old session has no authority", async t => {
  const store = new DurableRelayState(database(t)());
  paired(store);
  activate(store);
  store.commitVerifiedCommand(await signedInput("req-stale-1", "nonce-stale-1"), now);
  activate(store, 1, "rotated-session", "device-auth-rotated");
  assert.equal(store.leaseHead(deviceId, 1, "rotated-session", now, 10), null);
  assert.throws(() => store.leaseHead(deviceId, 1, fixture.session_id, now, 10),
    err => code(err, "SESSION_MISMATCH"));
  const staleInput = await signedInput("req-stale-2", "nonce-stale-2");
  assert.throws(() => store.commitVerifiedCommand(staleInput, now),
    err => code(err, "SESSION_MISMATCH"));
});

test("FIFO head cannot be bypassed until lease expires or result commits", async t => {
  const store = new DurableRelayState(database(t)());
  paired(store);
  activate(store);
  store.commitVerifiedCommand(await signedInput("req-fifo-1", "nonce-fifo-1"), now);
  store.commitVerifiedCommand(await signedInput("req-fifo-2", "nonce-fifo-2"), now);
  assert.equal(store.leaseHead(deviceId, 1, fixture.session_id, now, 10).requestId, "req-fifo-1");
  assert.equal(store.leaseHead(deviceId, 1, fixture.session_id, now + 2, 10), null);
  assert.equal(store.leaseHead(deviceId, 1, fixture.session_id, now + 10, 10).requestId, "req-fifo-1");
  store.completeResult(deviceId, 1, fixture.session_id, "req-fifo-1", '{"ok":true}', now + 10);
  assert.equal(store.leaseHead(deviceId, 1, fixture.session_id, now + 10, 10).requestId, "req-fifo-2");
});

test("failed command insert rolls back nonce claim and result failure keeps queue", async t => {
  const store = new DurableRelayState(database(t)());
  paired(store);
  activate(store);
  const first = await signedInput("req-atomic", "nonce-atomic-1");
  store.commitVerifiedCommand(first, now);
  const duplicate = await signedInput("req-atomic", "nonce-atomic-2");
  assert.throws(() => store.commitVerifiedCommand(duplicate, now),
    err => code(err, "DUPLICATE_REQUEST"));
  const retry = await signedInput("req-atomic-2", "nonce-atomic-2");
  store.commitVerifiedCommand(retry, now);

  assert.throws(() => store.completeResult(deviceId, 1, fixture.session_id,
    first.requestId, "x".repeat(65537), now), err => code(err, "INVALID_RESULT"));
  assert.equal(store.leaseHead(deviceId, 1, fixture.session_id, now, 10).requestId,
    first.requestId);
});

test("device and controller replay domains stay separate across recreation", t => {
  const open = database(t);
  const first = new DurableRelayState(open());
  paired(first);
  first.claimAssertionNonce("controller", deviceId, 1, "nonce-cross-domain", now + 60, now);
  first.claimAssertionNonce("device", deviceId, 1, "nonce-cross-domain", now + 60, now);
  const second = new DurableRelayState(open());
  assert.throws(() => second.claimAssertionNonce("controller", deviceId, 1,
    "nonce-cross-domain", now + 60, now), err => code(err, "REPLAY"));
  assert.throws(() => second.claimAssertionNonce("device", deviceId, 1,
    "nonce-cross-domain", now + 60, now), err => code(err, "REPLAY"));
});

test("revocation removes device trust, old queue and result without generation reuse", async t => {
  const open = database(t);
  const store = new DurableRelayState(open());
  paired(store);
  activate(store);
  const input = await signedInput("req-revoke", "nonce-revoke");
  store.commitVerifiedCommand(input, now);
  store.revokeAuthenticatedDevice(deviceId, 1);
  const second = new DurableRelayState(open());
  assert.equal(second.pairing(), null);
  assert.throws(() => second.activateAuthenticatedAgentSession(deviceId, 1,
    fixture.session_id, "after-revoke", now + 30, now), err => code(err, "PAIRING_MISMATCH"));
  assert.equal(second.resultForAuthorizedController === undefined, false);
  assert.equal(second.installVerifiedPairing(deviceId, deviceKey, controllerKey).generation, 2);
  second.activateAuthenticatedAgentSession(deviceId, 2, fixture.session_id,
    "new-generation", now + 30, now);
  assert.equal(second.leaseHead(deviceId, 2, fixture.session_id, now, 10), null);
  assert.throws(() => second.commitVerifiedCommand(input, now), err => code(err, "PAIRING_MISMATCH"));
});

test("replayed device session assertion does not rotate/prune valid FIFO", async t => {
  const store = new DurableRelayState(database(t)());
  paired(store);
  activate(store);
  const request = await signedInput("req-no-prune", "nonce-no-prune");
  store.commitVerifiedCommand(request, now);
  assert.throws(() => activate(store, 1, "unexpected-session", "device-auth-1"),
    err => code(err, "REPLAY"));
  assert.equal(store.leaseHead(deviceId, 1, fixture.session_id, now, 10).requestId,
    "req-no-prune");
});
