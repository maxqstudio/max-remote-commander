/**
 * P7A: protocol-v1 cryptographic compatibility boundary for a Cloudflare Worker.
 * No routing or durable replay authority is granted by this module.
 * Callers MUST provide a transactional, persistent ReplayRecorder.
 */
export type SignedKind = "device" | "controller" | "command";

export interface ReplayRecorder {
  // Must atomically persist nonce usage before returning true; false on replay.
  recordOnce(scope: SignedKind, deviceID: string, generation: number,
    nonce: string, expiresAt: number, now: number): Promise<boolean>;
}

export interface VerifyContext {
  deviceID: string;
  generation: number;
  agentSessionID: string;
  now: number; // UTC Unix seconds, not milliseconds
  maxClockSkewSeconds: number;
}

type Fields = Record<string, unknown>;

export class ProtocolError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
    this.name = "ProtocolError";
  }
}

function reject(code: string): never {
  throw new ProtocolError(code);
}

function isObject(value: unknown): value is Fields {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: unknown, keys: string[]): asserts value is Fields {
  if (!isObject(value) ||
      Object.keys(value).length !== keys.length ||
      Object.keys(value).some((key) => !keys.includes(key))) reject("INVALID_SHAPE");
  for (const key of keys) {
    if (!Object.hasOwn(value, key)) reject("INVALID_SHAPE");
  }
}

function identifier(value: unknown, maximum: number): asserts value is string {
  if (typeof value !== "string" ||
      value.length === 0 || value.length > maximum ||
      !/^[a-zA-Z0-9_.:-]+$/.test(value)) reject("INVALID_IDENTIFIER");
}

function positiveInteger(value: unknown): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    reject("INVALID_NUMBER");
  }
}

function timestamp(value: unknown): asserts value is number {
  positiveInteger(value);
}

function clock(now: number, skew: number): void {
  if (!Number.isSafeInteger(now) || now <= 0 ||
      !Number.isSafeInteger(skew) || skew < 0) reject("INVALID_CLOCK");
}

function lifetime(issued: number, expires: number, now: number,
  skew: number, maxLifetime: number): void {
  if (expires <= issued || expires - issued > maxLifetime) reject("INVALID_LIFETIME");
  if (expires <= now) reject("EXPIRED");
  if (issued > now + skew) reject("FUTURE_ISSUED");
}

function goString(value: string): string {
  // encoding/json uses HTML escaping; JSON.stringify does not.
  return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, (char) => {
    switch (char) {
      case "<": return "\\u003c";
      case ">": return "\\u003e";
      case "&": return "\\u0026";
      case "\u2028": return "\\u2028";
      default: return "\\u2029";
    }
  });
}

function compactRawJSON(raw: string): string {
  // Mirrors encoding/json's RawMessage compaction without reordering object keys.
  // This matters for JSON keys like "2" and "10" which JS object serialization reorders.
  JSON.parse(raw);
  let result = "";
  let insideString = false;
  let escaped = false;
  for (const char of raw) {
    if (insideString) {
      if (escaped) {
        result += char;
        escaped = false;
      } else if (char === "\\") {
        result += char;
        escaped = true;
      } else if (char === '"') {
        result += char;
        insideString = false;
      } else {
        result += char === "<" ? "\\u003c" :
          char === ">" ? "\\u003e" :
          char === "&" ? "\\u0026" :
          char === "\u2028" ? "\\u2028" :
          char === "\u2029" ? "\\u2029" : char;
      }
    } else if (char === '"') {
      result += char;
      insideString = true;
    } else if (char !== " " && char !== "\n" && char !== "\r" && char !== "\t") {
      result += char;
    }
  }
  return result;
}

function strictTopLevelFields(raw: string): Map<string, string> {
  if (raw.length > 1024 * 1024) reject("INVALID_SHAPE");
  // JSON.parse rejects invalid nesting, strings, and trailing data. The scan
  // additionally rejects duplicate keys and retains original RawMessage bytes.
  if (!isObject(JSON.parse(raw))) reject("INVALID_SHAPE");
  let i = 0;
  const skip = () => {
    while (i < raw.length && /[ \t\r\n]/.test(raw[i])) i++;
  };
  skip();
  if (raw[i++] !== "{") reject("INVALID_SHAPE");
  const fields = new Map<string, string>();
  skip();
  while (raw[i] !== "}") {
    if (raw[i] !== '"') reject("INVALID_SHAPE");
    const keyStart = i++;
    let escaped = false;
    while (i < raw.length) {
      const char = raw[i++];
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') break;
    }
    const key = JSON.parse(raw.slice(keyStart, i));
    if (typeof key !== "string" || fields.has(key)) reject("INVALID_SHAPE");
    skip();
    if (raw[i++] !== ":") reject("INVALID_SHAPE");
    skip();
    const valueStart = i;
    let depth = 0;
    let quoted = false;
    escaped = false;
    while (i < raw.length) {
      const char = raw[i];
      if (quoted) {
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === '"') quoted = false;
      } else if (char === '"') quoted = true;
      else if (char === "{" || char === "[") depth++;
      else if (char === "}" || char === "]") {
        if (depth === 0) break;
        depth--;
      } else if (char === "," && depth === 0) break;
      i++;
    }
    const fieldRaw = raw.slice(valueStart, i).trim();
    JSON.parse(fieldRaw);
    fields.set(key, fieldRaw);
    skip();
    if (raw[i] === ",") {
      i++;
      skip();
      continue;
    }
    if (raw[i] !== "}") reject("INVALID_SHAPE");
  }
  i++;
  skip();
  if (i !== raw.length) reject("INVALID_SHAPE");
  return fields;
}

function decodeBase64URL(value: unknown, expectedBytes: number): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) reject("INVALID_SIGNATURE");
  let bytes: Uint8Array;
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return reject("INVALID_SIGNATURE");
  }
  if (bytes.length !== expectedBytes) reject("INVALID_SIGNATURE");
  return bytes;
}

async function verifySignature(publicKey: string, signature: unknown,
  payload: string): Promise<void> {
  const publicBytes = decodeBase64URL(publicKey, 32);
  const signatureBytes = decodeBase64URL(signature, 64);
  const key = await crypto.subtle.importKey("raw", publicBytes, {name: "Ed25519"},
    false, ["verify"]);
  const verified = await crypto.subtle.verify("Ed25519", key, signatureBytes,
    new TextEncoder().encode(payload));
  if (!verified) reject("INVALID_SIGNATURE");
}

async function replay(scope: SignedKind, value: Fields, context: VerifyContext,
  recorder: ReplayRecorder): Promise<void> {
  if (!recorder || typeof recorder.recordOnce !== "function") reject("REPLAY_STORE_REQUIRED");
  const recorded = await recorder.recordOnce(scope, context.deviceID,
    context.generation, value.nonce as string, value.expires_at as number, context.now);
  if (!recorded) reject("REPLAY");
}

function assertionShape(value: unknown, kind: "device" | "controller"): Fields {
  const fields = kind === "device"
    ? ["device_id", "generation", "agent_session_id", "issued_at", "expires_at", "nonce", "signature"]
    : ["device_id", "generation", "issued_at", "expires_at", "nonce", "signature"];
  exactKeys(value, fields);
  identifier(value.device_id, 64);
  positiveInteger(value.generation);
  if (kind === "device") identifier(value.agent_session_id, 128);
  timestamp(value.issued_at);
  timestamp(value.expires_at);
  identifier(value.nonce, 128);
  if (typeof value.signature !== "string") reject("INVALID_SHAPE");
  return value;
}

function assertionCanonical(value: Fields, kind: "device" | "controller"): string {
  return '{"device_id":' + goString(value.device_id as string) +
    ',"generation":' + value.generation +
    (kind === "device" ? ',"agent_session_id":' + goString(value.agent_session_id as string) : "") +
    ',"issued_at":' + value.issued_at +
    ',"expires_at":' + value.expires_at +
    ',"nonce":' + goString(value.nonce as string) + "}";
}

export function canonicalDeviceAssertion(value: unknown): string {
  return assertionCanonical(assertionShape(value, "device"), "device");
}

export function canonicalControllerAssertion(value: unknown): string {
  return assertionCanonical(assertionShape(value, "controller"), "controller");
}

export async function verifyDeviceAssertion(value: unknown, publicKey: string,
  context: VerifyContext, recorder: ReplayRecorder): Promise<void> {
  const v = assertionShape(value, "device");
  clock(context.now, context.maxClockSkewSeconds);
  if (v.device_id !== context.deviceID || v.generation !== context.generation ||
      v.agent_session_id !== context.agentSessionID) reject("WRONG_BINDING");
  lifetime(v.issued_at as number, v.expires_at as number, context.now,
    context.maxClockSkewSeconds, 60);
  await verifySignature(publicKey, v.signature, assertionCanonical(v, "device"));
  await replay("device", v, context, recorder);
}

export async function verifyControllerAssertion(value: unknown, publicKey: string,
  context: VerifyContext, recorder: ReplayRecorder): Promise<void> {
  const v = assertionShape(value, "controller");
  clock(context.now, context.maxClockSkewSeconds);
  if (v.device_id !== context.deviceID || v.generation !== context.generation) {
    reject("WRONG_BINDING");
  }
  lifetime(v.issued_at as number, v.expires_at as number, context.now,
    context.maxClockSkewSeconds, 60);
  await verifySignature(publicKey, v.signature, assertionCanonical(v, "controller"));
  await replay("controller", v, context, recorder);
}

function commandFields(raw: string): {value: Fields; argumentsJSON: string} {
  const fields = strictTopLevelFields(raw);
  const keys = ["version", "request_id", "device_id", "session_id",
    "issued_at", "expires_at", "nonce", "tool", "arguments", "signature"];
  if (fields.size !== keys.length || [...fields.keys()].some((key) => !keys.includes(key))) {
    reject("INVALID_SHAPE");
  }
  const value = JSON.parse(raw) as Fields;
  exactKeys(value, keys);
  if (value.version !== 1) reject("INVALID_VERSION");
  identifier(value.request_id, 128);
  identifier(value.device_id, 64);
  identifier(value.session_id, 128);
  identifier(value.nonce, 128);
  if (typeof value.tool !== "string" || value.tool.length === 0) reject("INVALID_SHAPE");
  timestamp(value.issued_at);
  timestamp(value.expires_at);
  if (typeof value.signature !== "string") reject("INVALID_SHAPE");
  const argumentsJSON = fields.get("arguments");
  if (!argumentsJSON) reject("INVALID_SHAPE");
  return {value, argumentsJSON};
}

export function canonicalCommandEnvelope(raw: string): string {
  const {value: v, argumentsJSON} = commandFields(raw);
  return '{"version":1,"request_id":' + goString(v.request_id as string) +
    ',"device_id":' + goString(v.device_id as string) +
    ',"session_id":' + goString(v.session_id as string) +
    ',"issued_at":' + v.issued_at +
    ',"expires_at":' + v.expires_at +
    ',"nonce":' + goString(v.nonce as string) +
    ',"tool":' + goString(v.tool as string) +
    ',"arguments":' + compactRawJSON(argumentsJSON) + "}";
}

export async function verifySignedCommand(raw: string, publicKey: string,
  context: VerifyContext, recorder: ReplayRecorder): Promise<void> {
  const {value: v} = commandFields(raw);
  clock(context.now, context.maxClockSkewSeconds);
  if (v.device_id !== context.deviceID || v.session_id !== context.agentSessionID) {
    reject("WRONG_BINDING");
  }
  lifetime(v.issued_at as number, v.expires_at as number, context.now,
    context.maxClockSkewSeconds, 300);
  await verifySignature(publicKey, v.signature, canonicalCommandEnvelope(raw));
  await replay("command", v, context, recorder);
}
