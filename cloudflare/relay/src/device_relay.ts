/**
 * Cloudflare per-device SQLite Durable Object. All authorization for
 * externally reachable operations is checked here, not on trusted headers.
 * Only fetch() is a public class method; helpers are module-local.
 */
import { DurableObject } from "cloudflare:workers";
import { DurableRelayState, DurableStateError } from "./state";
import { ProtocolError, verifyAssertionSignature, verifySignedCommandSignature, verifySignedCommand,
  extractRawObjectField } from "./protocol";
import type { Env } from "./index";

type TokenAuthority = {
  tokenHash: Uint8Array;
  deviceId: string;
  generation: number;
  agentSessionId: string;
  expiresAt: number;
};

type Offer = {
  codeHash: Uint8Array;
  devicePublicKey: string;
  deviceId: string;
  expiresAt: number;
  attempts: number;
  receiptHash: Uint8Array;
  receiptExpiresAt: number;
};

const idPattern = /^dev_[A-Za-z0-9_-]{43}$/;
const keyPattern = /^[A-Za-z0-9_-]{43}$/;
const reqPattern = /^[A-Za-z0-9._:-]{1,128}$/;
const utf8 = new TextEncoder();

function respond(status: number, body?: unknown): Response {
  return body === undefined ? new Response(null, { status }) :
    Response.json(body, { status });
}
function bytesToUrl(bytes: Uint8Array): string {
  let value = "";
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function urlToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("invalid encoding");
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
async function digest(value: Uint8Array | string): Promise<Uint8Array> {
  const data = typeof value === "string" ? utf8.encode(value) : value;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let delta = 0;
  for (let i = 0; i < a.length; i++) delta |= a[i] ^ b[i];
  return delta === 0;
}
function token(): string {
  return bytesToUrl(crypto.getRandomValues(new Uint8Array(32)));
}
function bearer(request: Request): string {
  const raw = request.headers.get("authorization") || "";
  return /^Bearer [A-Za-z0-9_-]{43}$/.test(raw) ? raw.slice(7) : "";
}
async function authenticates(request: Request, authority: TokenAuthority | null,
  deviceId: string, pairing: { generation: number } | null, now: number): Promise<boolean> {
  const value = bearer(request);
  if (!value || !authority || !pairing || deviceId !== authority.deviceId ||
    pairing.generation !== authority.generation || authority.expiresAt <= now)
    return false;
  return sameBytes(await digest(value), authority.tokenHash);
}
async function readBody(request: Request): Promise<string> {
  const len = Number(request.headers.get("content-length"));
  if (len > 65536) throw new DurableStateError("OVERSIZE");
  const text = await request.text();
  if (utf8.encode(text).byteLength > 65536) throw new DurableStateError("OVERSIZE");
  return text;
}
function objectBody(wire: string, keys: string[]): Record<string, unknown> {
  let value: unknown;
  try { value = JSON.parse(wire); } catch { throw new DurableStateError("INVALID_JSON"); }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new DurableStateError("INVALID_JSON");
  const fields = Object.keys(value);
  if (fields.length !== keys.length || fields.some(key => !keys.includes(key)))
    throw new DurableStateError("INVALID_JSON");
  return value as Record<string, unknown>;
}
async function matchesDeviceKey(deviceId: string, publicKey: string): Promise<boolean> {
  if (!idPattern.test(deviceId) || !keyPattern.test(publicKey)) return false;
  const decoded = urlToBytes(publicKey);
  return decoded.length === 32 && deviceId === "dev_" + bytesToUrl(await digest(decoded));
}
function iso(expiresAt: number): string {
  return new Date(expiresAt * 1000).toISOString();
}
function failure(error: unknown): Response {
  if (error instanceof ProtocolError) return respond(401, { error: "invalid_signature_or_assertion" });
  if (error instanceof DurableStateError) {
    switch (error.code) {
      case "REPLAY":
      case "DUPLICATE_REQUEST":
      case "SESSION_MISMATCH":
      case "SESSION_EXPIRED":
      case "PAIRING_MISMATCH":
      case "ALREADY_PAIRED":
        return respond(409, { error: error.code });
      case "QUEUE_FULL":
        return respond(429, { error: "queue_full" });
      default:
        return respond(400, { error: "invalid_request" });
    }
  }
  // Never include exception internals in public responses.
  return respond(500, { error: "internal_error" });
}

export class DeviceRelay extends DurableObject<Env> {
  #store: DurableRelayState;
  #device: TokenAuthority | null = null;
  #controller: TokenAuthority | null = null;
  #offer: Offer | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#store = new DurableRelayState(ctx.storage);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const match = /^\/v1\/devices\/([^/]+)\/(.+)$/.exec(url.pathname);
    if (!match || !idPattern.test(match[1])) return respond(404, { error: "not_found" });
    const deviceId = match[1];
    const operation = match[2];
    const now = Math.floor(Date.now() / 1000);
    const pairing = this.#store.pairing();

    try {
      if (request.method === "POST" && operation === "pairing-offer") {
        // Enrolment secret has no controller, command, or result authority.
        // Missing secret means public enrolment is disabled, never open.
        const secret = this.env.PAIRING_BOOTSTRAP_SECRET;
        if (!secret || secret.length < 32) return respond(503, { error: "enrolment_disabled" });
        const value = request.headers.get("authorization") || "";
        if (!value.startsWith("Bearer ") ||
          !sameBytes(await digest(value.slice(7)), await digest(secret)))
          return respond(401, { error: "unauthorized" });
        if (pairing) return respond(409, { error: "already_paired" });
        const body = objectBody(await readBody(request),
          ["code_hash", "device_public_key", "ttl_seconds"]);
        if (typeof body.code_hash !== "string" ||
          typeof body.device_public_key !== "string" ||
          !Number.isSafeInteger(body.ttl_seconds) || (body.ttl_seconds as number) < 1 ||
          (body.ttl_seconds as number) > 300 ||
          !/^[A-Za-z0-9_-]{43}$/.test(body.code_hash) ||
          !await matchesDeviceKey(deviceId, body.device_public_key))
          return respond(400, { error: "invalid_offer" });
        const rawHash = urlToBytes(body.code_hash);
        if (rawHash.length !== 32 || sameBytes(rawHash, await digest("")))
          return respond(400, { error: "invalid_offer" });
        const receipt = token();
        this.#offer = {
          codeHash: rawHash, devicePublicKey: body.device_public_key,
          deviceId, expiresAt: now + (body.ttl_seconds as number), attempts: 0,
          receiptHash: await digest(receipt), receiptExpiresAt: now + 600,
        };
        return respond(201, {
          status: "pairing-offer-created", receipt_token: receipt,
          receipt_expires_at: iso(this.#offer.receiptExpiresAt),
        });
      }
      if (request.method === "GET" && operation === "pairing/status") {
        if (!this.#offer || this.#offer.deviceId !== deviceId ||
          this.#offer.receiptExpiresAt <= now ||
          !sameBytes(await digest(bearer(request)), this.#offer.receiptHash))
          return respond(401, { error: "unauthorized" });
        const paired = this.#store.pairing();
        return paired ? respond(200, {
          device_id: paired.deviceId, generation: paired.generation,
          controller_public_key: paired.controllerPublicKey,
        }) : respond(204);
      }
      if (request.method === "POST" && operation === "pairing/redeem") {
        if (pairing) return respond(409, { error: "already_paired" });
        const body = objectBody(await readBody(request), ["code", "controller_public_key"]);
        const offer = this.#offer;
        if (!offer || offer.deviceId !== deviceId) return respond(404, { error: "offer_missing" });
        if (offer.expiresAt <= now) {
          this.#offer = null;
          return respond(410, { error: "offer_expired" });
        }
        if (typeof body.code !== "string" || body.code.length > 256 ||
          typeof body.controller_public_key !== "string" || !keyPattern.test(body.controller_public_key))
          return respond(400, { error: "invalid_request" });
        if (!sameBytes(await digest(body.code), offer.codeHash)) {
          offer.attempts++;
          if (offer.attempts >= 5) this.#offer = null;
          return respond(401, { error: "pairing_code_invalid" });
        }
        const accepted = this.#store.installVerifiedPairing(deviceId,
          offer.devicePublicKey, body.controller_public_key);
        return respond(201, { device_id: accepted.deviceId, generation: accepted.generation });
      }
      if (request.method === "POST" && operation === "session") {
        if (!pairing || pairing.deviceId !== deviceId)
          return respond(404, { error: "not_paired" });
        const wire = await readBody(request);
        const value = await verifyAssertionSignature("device", wire, {
          deviceId, generation: pairing.generation, publicKey: pairing.devicePublicKey,
          now, clockSkewSeconds: 30,
        });
        const sessionId = value.agent_session_id as string;
        const expiresAt = now + 900;
        const issued = token();
        this.#store.activateAuthenticatedAgentSession(deviceId, pairing.generation,
          sessionId, value.nonce as string, value.expires_at as number, now, expiresAt);
        this.#device = {
          tokenHash: await digest(issued), deviceId, generation: pairing.generation,
          agentSessionId: sessionId, expiresAt,
        };
        this.#controller = null;
        for (const socket of this.ctx.getWebSockets()) {
          const attached = socket.deserializeAttachment() as {
            deviceId?: string; generation?: number; agentSessionId?: string;
          } | null;
          if (attached?.deviceId === deviceId &&
              attached.generation === pairing.generation &&
              attached.agentSessionId === sessionId) {
            socket.serializeAttachment({
              deviceId, generation: pairing.generation,
              agentSessionId: sessionId, expiresAt,
            });
          } else {
            try { socket.close(1008, "stale session"); } catch { /* disconnected */ }
          }
        }
        return respond(201, {
          token: issued, expires_at: iso(expiresAt), agent_session_id: sessionId,
          generation: pairing.generation,
        });
      }
      if (request.method === "POST" && operation === "controller-session") {
        if (!pairing || pairing.deviceId !== deviceId)
          return respond(404, { error: "not_paired" });
        if (!this.#device || this.#device.expiresAt <= now ||
          this.#device.generation !== pairing.generation)
          return respond(409, { error: "device_offline" });
        const wire = await readBody(request);
        const value = await verifyAssertionSignature("controller", wire, {
          deviceId, generation: pairing.generation, publicKey: pairing.controllerPublicKey,
          now, clockSkewSeconds: 30,
        });
        const issued = token();
        this.#store.claimAssertionNonce("controller", deviceId, pairing.generation,
          value.nonce as string, value.expires_at as number, now);
        this.#controller = {
          tokenHash: await digest(issued), deviceId, generation: pairing.generation,
          agentSessionId: this.#device.agentSessionId, expiresAt: now + 900,
        };
        return respond(201, {
          token: issued, expires_at: iso(this.#controller.expiresAt),
          device_id: deviceId, generation: pairing.generation,
          agent_session_id: this.#device.agentSessionId,
        });
      }
      if (request.method === "DELETE" && operation === "pairing") {
        if (!await authenticates(request, this.#device, deviceId, pairing, now))
          return respond(401, { error: "unauthorized" });
        this.#store.revokeAuthenticatedDevice(deviceId, pairing!.generation);
        this.#device = null;
        this.#controller = null;
        this.#offer = null;
        return respond(204);
      }

      if (request.method === "POST" && operation === "commands")
        return await this.queueCommand(request, deviceId, now);
      if (request.method === "GET" && operation === "commands/next") {
        const pairingNow = this.#store.pairing();
        if (!await authenticates(request, this.#device, deviceId, pairingNow, now))
          return respond(401, { error: "unauthorized" });
        if (url.searchParams.has("wait_ms") && url.searchParams.get("wait_ms") !== "0")
          return respond(400, { error: "only_nonblocking_supported" });
        const head = this.#store.leaseHead(deviceId, pairingNow!.generation,
          this.#device!.agentSessionId, now, 15);
        return head ? respond(200, {
          request_id: head.requestId, payload: JSON.parse(head.envelopeJSON),
        }) : respond(204);
      }
      if (request.method === "POST" && operation === "results")
        return await this.submitResult(request, deviceId, now);
      const resultMatch = /^results\/([A-Za-z0-9._:-]{1,128})$/.exec(operation);
      if (request.method === "GET" && resultMatch)
        return await this.waitResult(request, deviceId, resultMatch[1], now);
      if (request.method === "GET" && operation === "stream")
        return await this.acceptAgentSocket(request, deviceId, now);
      return respond(404, { error: "not_found" });
    } catch (error) {
      return failure(error);
    }
  }

  private async queueCommand(request: Request, deviceId: string, now: number): Promise<Response> {
    const pairing = this.#store.pairing();
    if (!await authenticates(request, this.#controller, deviceId, pairing, now) ||
        !this.#device || this.#device.expiresAt <= now ||
        this.#controller?.agentSessionId !== this.#device.agentSessionId)
      return respond(401, { error: "unauthorized" });
    const parts = extractRawObjectField(await readBody(request),
      ["request_id", "payload"], "payload");
    const requestId = parts.value.request_id;
    if (typeof requestId !== "string" || !reqPattern.test(requestId))
      return respond(400, { error: "invalid_request" });
    // The ReplayGate callback atomically claims nonce + inserts the command.
    // This avoids spending a nonce if insertion fails after signature verification.
    const authority = {
      deviceId, generation: pairing!.generation,
      agentSessionId: this.#controller.agentSessionId,
      publicKey: pairing!.controllerPublicKey, now, clockSkewSeconds: 30,
    };
    const value = await verifySignedCommandSignature(parts.raw, authority);
    if (value.request_id !== requestId) return respond(400, { error: "request_id_mismatch" });
    await verifySignedCommand(parts.raw, {
      ...authority,
      replay: {
        use: async (_domain, _deviceId, _generation, nonce, expiresAt, timestamp) => {
          this.#store.commitVerifiedCommand({
            requestId, deviceId, generation: pairing!.generation,
            agentSessionId: value.session_id as string,
            nonce, issuedAt: value.issued_at as number,
            expiresAt, envelopeJSON: parts.raw,
          }, timestamp);
          return true;
        },
      },
    });
    await this.deliverHead(deviceId, now);
    return respond(202, { status: "queued" });
  }

  private async submitResult(request: Request, deviceId: string, now: number): Promise<Response> {
    const pairing = this.#store.pairing();
    if (!await authenticates(request, this.#device, deviceId, pairing, now))
      return respond(401, { error: "unauthorized" });
    const parts = extractRawObjectField(await readBody(request),
      ["request_id", "payload"], "payload");
    const requestId = parts.value.request_id;
    if (typeof requestId !== "string" || !reqPattern.test(requestId))
      return respond(400, { error: "invalid_request" });
    this.#store.completeResult(deviceId, pairing!.generation,
      this.#device!.agentSessionId, requestId, parts.raw, now);
    await this.deliverHead(deviceId, now);
    return respond(202, { status: "accepted" });
  }

  private async waitResult(request: Request, deviceId: string,
    requestId: string, now: number): Promise<Response> {
    const pairing = this.#store.pairing();
    if (!await authenticates(request, this.#controller, deviceId, pairing, now) ||
        !this.#device || this.#device.expiresAt <= now ||
        this.#controller?.agentSessionId !== this.#device.agentSessionId)
      return respond(401, { error: "unauthorized" });
    const result = this.#store.resultForAuthorizedController(deviceId,
      pairing!.generation, requestId, now);
    return result ? respond(200, {
      request_id: result.requestId, payload: JSON.parse(result.payload),
    }) : respond(204);
  }

  private async acceptAgentSocket(request: Request, deviceId: string, now: number):
    Promise<Response> {
    const pairing = this.#store.pairing();
    if (!await authenticates(request, this.#device, deviceId, pairing, now))
      return respond(401, { error: "unauthorized" });
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket")
      return respond(426, { error: "upgrade_required" });
    for (const current of this.ctx.getWebSockets()) {
      try { current.close(1000, "replaced"); } catch { /* disconnected */ }
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({
      deviceId, generation: pairing!.generation,
      agentSessionId: this.#device!.agentSessionId,
      expiresAt: this.#device!.expiresAt,
    });
    this.ctx.acceptWebSocket(server);
    await this.deliverHead(deviceId, now);
    return new Response(null, { status: 101, webSocket: client });
  }

  /**
   * Deliver one FIFO head only after a durable queue commit and on an
   * authenticated outbound agent socket. No inbound PC listener is used.
   */
  private async deliverHead(deviceId: string, now: number): Promise<void> {
    const pairing = this.#store.pairing();
    const agent = this.#device;
    if (!pairing || !agent || agent.deviceId !== deviceId || agent.expiresAt <= now ||
        agent.generation !== pairing.generation) return;
    for (const socket of this.ctx.getWebSockets()) {
      const att = socket.deserializeAttachment() as {
        deviceId?: string; generation?: number; agentSessionId?: string; expiresAt?: number;
      } | null;
      if (!att || att.deviceId !== deviceId || att.generation !== pairing.generation ||
          att.agentSessionId !== agent.agentSessionId || !att.expiresAt ||
          att.expiresAt <= now) continue;
      const next = this.#store.leaseHead(deviceId, pairing.generation,
        agent.agentSessionId, now, 15);
      if (!next) return;
      const frame = JSON.stringify({ version: 1, type: "command",
        request_id: next.requestId, payload: JSON.parse(next.envelopeJSON) });
      try {
        socket.send(frame);
      } catch {
        try { socket.close(1011, "send failed"); } catch { /* disconnected */ }
        throw new DurableStateError("SOCKET_SEND_FAILED");
      }
      // The alarm retries the FIFO lease if no durable result is acknowledged.
      await this.ctx.storage.setAlarm((now + 16) * 1000);
      return;
    }
  }

  async alarm(): Promise<void> {
    const pairing = this.#store.pairing();
    if (pairing) await this.deliverHead(pairing.deviceId, Math.floor(Date.now() / 1000));
  }

  webSocketMessage(socket: WebSocket, _message: string | ArrayBuffer): void {
    // Agent stream is one-way for command delivery. Results use authenticated HTTPS.
    socket.close(1008, "unexpected agent frame");
  }

  webSocketClose(socket: WebSocket, code: number, reason: string): void {
    try { socket.close(code, reason); } catch { /* closed */ }
  }

  webSocketError(socket: WebSocket): void {
    try { socket.close(1011, "connection error"); } catch { /* closed */ }
  }
}
