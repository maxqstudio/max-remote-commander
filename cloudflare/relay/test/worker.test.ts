import { describe, it, expect } from "vitest";
import { env, exports } from "cloudflare:workers";
import { runInDurableObject, evictDurableObject } from "cloudflare:test";
import { DurableRelayState } from "../src/state";

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
    expect(enrollment.status).toBe(503);
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
