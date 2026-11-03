import { describe, it, expect } from "vitest";
import { env, exports } from "cloudflare:workers";
import { runInDurableObject, evictDurableObject } from "cloudflare:test";
import { DurableRelayState } from "../src/state";
import { canonicalAssertion, canonicalCommand } from "../src/protocol";

const deviceId = "dev_" + "A".repeat(43);
const deviceKey = "A".repeat(43);
const controllerKey = "B".repeat(43);

describe("P7B real workerd SQLite Durable Object", () => {
  it("public Worker routes, no CORS and no exposed bootstrap", async () => {
    const ok = await exports.default.fetch("https://example.invalid/healthz");
    expect(ok.status).toBe(200);
    expect(ok.headers.get("cache-control")).toBe("no-store");
    expect(ok.headers.has("access-control-allow-origin")).toBe(false);
    const missing = await exports.default.fetch("https://example.invalid/v1/devices/not-a-device/commands");
    expect(missing.status).toBe(404);
    const unauthorized = await exports.default.fetch(
      "https://example.invalid/v1/devices/" + deviceId + "/commands",
      { method: "POST", body: "{}" });
    expect(unauthorized.status).toBe(401);
    const enrollment = await exports.default.fetch(
      "https://example.invalid/v1/devices/" + deviceId + "/pairing-offer",
      { method: "POST", body: "{}" });
    expect(enrollment.status).toBe(401);
  });

  it("trust and result survive eviction; short-lived bearer session does not", async () => {
    const stub = env.DEVICE_RELAY.get(env.DEVICE_RELAY.idFromName(deviceId + "-storage"));
    await runInDurableObject(stub, async (_instance, state) => {
      const store = new DurableRelayState(state.storage);
      const trust = store.installVerifiedPairing(deviceId, deviceKey, controllerKey);
      expect(trust.generation).toBe(1);
      store.activateAuthenticatedAgentSession(deviceId, 1, "session-1",
        "device-nonce-1", 2000000060, 2000000000, 2000000900);
      store.commitVerifiedCommand({
        requestId: "req-p7b-1", deviceId, generation: 1, agentSessionId: "session-1",
        nonce: "nonce-p7b-1", issuedAt: 2000000000, expiresAt: 2000000060,
        envelopeJSON: JSON.stringify({ request_id: "req-p7b-1", device_id: deviceId,
          session_id: "session-1", nonce: "nonce-p7b-1",
          issued_at: 2000000000, expires_at: 2000000060 }),
      }, 2000000000);
      store.completeResult(deviceId, 1, "session-1",
        "req-p7b-1", '{"ok":true}', 2000000000);
    });
    await evictDurableObject(stub);
    await runInDurableObject(stub, async (_instance, state) => {
      const store = new DurableRelayState(state.storage);
      expect(store.pairing()?.generation).toBe(1);
      expect(store.resultForAuthorizedController(deviceId, 1, "req-p7b-1", 2000000000)?.payload)
        .toBe('{"ok":true}');
      expect(() => store.leaseHead(deviceId, 1, "session-1", 2000000000, 10))
        .toThrow("SESSION_MISMATCH");
      expect(() => store.claimAssertionNonce("device", deviceId, 1,
        "device-nonce-1", 2000000060, 2000000000)).toThrow("REPLAY");
    });
  });

  it("one device ID cannot access another device's trust", async () => {
    const first = env.DEVICE_RELAY.get(env.DEVICE_RELAY.idFromName("test-isolated-1"));
    const second = env.DEVICE_RELAY.get(env.DEVICE_RELAY.idFromName("test-isolated-2"));
    await runInDurableObject(first, async (_instance, state) => {
      new DurableRelayState(state.storage).installVerifiedPairing(deviceId, deviceKey, controllerKey);
    });
    await runInDurableObject(second, async (_instance, state) => {
      expect(new DurableRelayState(state.storage).pairing()).toBeNull();
    });
  });
});


function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function sha256(input: Uint8Array | string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256",
    typeof input === "string" ? new TextEncoder().encode(input) : input));
}
async function newIdentity() {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return {
    privateKey: pair.privateKey, publicKey: base64url(publicBytes),
    deviceId: "dev_" + base64url(await sha256(publicBytes)),
  };
}
async function signedAssertion(kind: "device" | "controller",
  data: Record<string, unknown>, privateKey: CryptoKey) {
  const payload = { ...data, signature: "" };
  const canonical = canonicalAssertion(kind, JSON.stringify(payload));
  payload.signature = base64url(new Uint8Array(await crypto.subtle.sign(
    "Ed25519", privateKey, new TextEncoder().encode(canonical))));
  return payload;
}
async function signedCommand(data: Record<string, unknown>, privateKey: CryptoKey) {
  const payload = { ...data, signature: "" };
  const canonical = canonicalCommand(JSON.stringify(payload));
  payload.signature = base64url(new Uint8Array(await crypto.subtle.sign(
    "Ed25519", privateKey, new TextEncoder().encode(canonical))));
  return payload;
}
async function call(deviceId: string, path: string, method = "GET", token = "",
  payload?: Record<string, unknown>): Promise<Response> {
  return exports.default.fetch("https://example.invalid/v1/devices/" + deviceId + "/" + path, {
    method,
    headers: {
      ...(token ? { Authorization: "Bearer " + token } : {}),
      ...(payload ? { "Content-Type": "application/json" } : {}),
    },
    ...(payload ? { body: JSON.stringify(payload) } : {}),
  });
}

describe("P7A real Workerd paired command/result control flow", () => {
  it("authenticates paired identities, verifies signed commands, blocks replay, and revokes", async () => {
    const device = await newIdentity();
    const controller = await newIdentity();
    const code = "WORKERD-TEST-PAIRING-2026";
    const codeHash = base64url(await sha256(code));

    const offered = await call(device.deviceId, "pairing-offer", "POST",
      "ci-fixture-nonproduction-bootstrap-token-64-bytes-1234567890123456", {
        code_hash: codeHash, device_public_key: device.publicKey, ttl_seconds: 300,
      });
    expect(offered.status).toBe(201);
    const receipt = await offered.json() as {receipt_token: string};
    expect(receipt.receipt_token.length).toBe(43);
    expect((await call(device.deviceId, "pairing/status", "GET", receipt.receipt_token)).status)
      .toBe(204);
    const wrongCode = await call(device.deviceId, "pairing/redeem", "POST", "", {
      code: code + "-wrong", controller_public_key: controller.publicKey,
    });
    expect(wrongCode.status).toBe(401);
    const redeemed = await call(device.deviceId, "pairing/redeem", "POST", "", {
      code, controller_public_key: controller.publicKey,
    });
    expect(redeemed.status).toBe(201);
    expect((await redeemed.json() as {generation:number}).generation).toBe(1);
    expect((await call(device.deviceId, "pairing/status", "GET", receipt.receipt_token)).status)
      .toBe(200);
    const now = Math.floor(Date.now() / 1000);
    const agentSessionId = "workerd-agent-session";
    const deviceProof = await signedAssertion("device", {
      device_id: device.deviceId, generation: 1, agent_session_id: agentSessionId,
      issued_at: now, expires_at: now + 60, nonce: "agent-assertion-1",
    }, device.privateKey);
    const deviceSession = await call(device.deviceId, "session", "POST", "", deviceProof);
    expect(deviceSession.status).toBe(201);
    const deviceToken = (await deviceSession.json() as {token:string}).token;
    expect((await call(device.deviceId, "session", "POST", "", deviceProof)).status).toBe(409);

    const controllerProof = await signedAssertion("controller", {
      device_id: device.deviceId, generation: 1,
      issued_at: now, expires_at: now + 60, nonce: "controller-assertion-1",
    }, controller.privateKey);
    const controllerSession = await call(device.deviceId, "controller-session", "POST", "",
      controllerProof);
    expect(controllerSession.status).toBe(201);
    const controllerToken = (await controllerSession.json() as {token:string}).token;
    // The device initiates an outbound-only authenticated stream.
    const stream = await exports.default.fetch(
      "https://example.invalid/v1/devices/" + device.deviceId + "/stream",
      { headers: { Upgrade: "websocket", Authorization: "Bearer " + deviceToken } },
    );
    expect(stream.status).toBe(101);
    const socket = stream.webSocket;
    expect(socket).toBeDefined();
    socket!.accept();
    const pushed = new Promise<string>((resolve, reject) => {
      socket!.addEventListener("message", event => resolve(event.data as string), { once: true });
      socket!.addEventListener("close", () => reject(new Error("stream closed before delivery")),
        { once: true });
    });
    const command = await signedCommand({
      version: 1, request_id: "req-workerd-auth", device_id: device.deviceId,
      session_id: agentSessionId, issued_at: now, expires_at: now + 60,
      nonce: "cmd-workerd-nonce", tool: "system.health", arguments: {},
    }, controller.privateKey);
    const wrapper = {request_id: "req-workerd-auth", payload: command};
    expect((await call(device.deviceId, "commands", "POST", deviceToken, wrapper)).status)
      .toBe(401);
    expect((await call(device.deviceId, "commands", "POST", controllerToken, wrapper)).status)
      .toBe(202);
    expect((await call(device.deviceId, "commands", "POST", controllerToken, wrapper)).status)
      .toBe(409);
    const frame = JSON.parse(await pushed) as {
      version: number; type: string; request_id: string; payload: { request_id: string };
    };
    expect(frame.version).toBe(1);
    expect(frame.type).toBe("command");
    expect(frame.request_id).toBe("req-workerd-auth");
    expect(frame.payload.request_id).toBe("req-workerd-auth");
    // Head-of-line remains leased until a device result arrives.
    expect((await call(device.deviceId, "commands/next?wait_ms=0", "GET",
      deviceToken)).status).toBe(204);
    expect((await call(device.deviceId, "results/req-workerd-auth", "GET",
      deviceToken)).status).toBe(401);
    expect((await call(device.deviceId, "results", "POST", deviceToken, {
      request_id: "req-workerd-auth", payload: { status: "completed" },
    })).status).toBe(202);
    const result = await call(device.deviceId, "results/req-workerd-auth", "GET",
      controllerToken);
    expect(result.status).toBe(200);
    expect((await result.json() as {payload:{status:string}}).payload.status).toBe("completed");
    // Eviction preserves the socket + SQLite but invalidates bearer authority.
    const stub = env.DEVICE_RELAY.get(env.DEVICE_RELAY.idFromName(device.deviceId));
    await evictDurableObject(stub);
    expect((await call(device.deviceId, "commands/next", "GET", deviceToken)).status).toBe(401);

    const resumedProof = await signedAssertion("device", {
      device_id: device.deviceId, generation: 1, agent_session_id: agentSessionId,
      issued_at: now, expires_at: now + 60, nonce: "agent-assertion-after-eviction",
    }, device.privateKey);
    const resumedDevice = await call(device.deviceId, "session", "POST", "", resumedProof);
    expect(resumedDevice.status).toBe(201);
    const resumedDeviceToken = (await resumedDevice.json() as {token:string}).token;
    const resumedControllerProof = await signedAssertion("controller", {
      device_id: device.deviceId, generation: 1,
      issued_at: now, expires_at: now + 60, nonce: "controller-after-eviction",
    }, controller.privateKey);
    const resumedController = await call(device.deviceId, "controller-session", "POST", "",
      resumedControllerProof);
    expect(resumedController.status).toBe(201);
    const resumedControllerToken = (await resumedController.json() as {token:string}).token;
    expect((await call(device.deviceId, "commands", "POST", controllerToken,
      { request_id: "invalid-old-token", payload: command })).status).toBe(401);

    const rePushed = new Promise<string>((resolve, reject) => {
      socket!.addEventListener("message", event => resolve(event.data as string), { once: true });
      socket!.addEventListener("close", () => reject(new Error("hibernated socket closed")),
        { once: true });
    });
    const nextCommand = await signedCommand({
      version: 1, request_id: "req-after-hibernation", device_id: device.deviceId,
      session_id: agentSessionId, issued_at: now, expires_at: now + 60,
      nonce: "cmd-after-hibernation", tool: "system.health", arguments: {},
    }, controller.privateKey);
    expect((await call(device.deviceId, "commands", "POST", resumedControllerToken,
      { request_id: "req-after-hibernation", payload: nextCommand })).status).toBe(202);
    expect((JSON.parse(await rePushed) as {request_id:string}).request_id)
      .toBe("req-after-hibernation");
    expect((await call(device.deviceId, "results", "POST", resumedDeviceToken, {
      request_id: "req-after-hibernation", payload: {status: "after-hibernation"},
    })).status).toBe(202);
    expect((await call(device.deviceId, "results/req-after-hibernation", "GET",
      resumedControllerToken)).status).toBe(200);
    socket!.close(1000, "done");

    expect((await call(device.deviceId, "pairing", "DELETE", controllerToken)).status).toBe(401);
    expect((await call(device.deviceId, "pairing", "DELETE", resumedDeviceToken)).status).toBe(204);
    expect((await call(device.deviceId, "commands/next", "GET", deviceToken)).status).toBe(401);
  });
});
