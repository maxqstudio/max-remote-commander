/**
 * Protocol-v1 cryptographic verifier for Cloudflare's WebCrypto runtime.
 * This module does not create sessions or grant execution approval.
 * Public keys and bindings must come from the trusted paired-device state.
 */

export class ProtocolError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
    this.name = "ProtocolError";
  }
}

export interface ReplayGate {
  // Must be atomic and durable in the Durable Object implementation.
  use(deviceId: string, generation: number, nonce: string, expiresAt: number, now: number): Promise<boolean>;
}

export interface PairedAuthority {
  deviceId: string;
  generation: number;
  publicKey: string;
  now: number;
  clockSkewSeconds: number;
  replay: ReplayGate;
}

export interface CommandAuthority extends PairedAuthority {
  agentSessionId: string;
}

const encoder = new TextEncoder();
const idPattern = /^[a-zA-Z0-9._:-]+$/;

function fail(code: string): never {
  throw new ProtocolError(code);
}

function id(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max && idPattern.test(value);
}

function positiveInt(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function b64url(value: string, bytes: number): Uint8Array {
  if (!/^[a-zA-Z0-9_-]+$/.test(value) || value.length % 4 === 1) fail("INVALID_ENCODING");
  let binary: string;
  try {
    binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  } catch {
    return fail("INVALID_ENCODING");
  }
  if (binary.length !== bytes) fail("INVALID_ENCODING");
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function quoted(value: string): string {
  return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, c => {
    const code = c.charCodeAt(0).toString(16).padStart(4, "0");
    return "\\u" + code;
  });
}

function skipWhitespace(text: string, offset: number): number {
  while (offset < text.length && /[\x20\t\n\r]/.test(text[offset])) offset++;
  return offset;
}

function scanString(text: string, start: number): number {
  if (text[start] !== '"') fail("INVALID_JSON");
  for (let i = start + 1; i < text.length; i++) {
    if (text[i] === "\\") {
      i++;
      continue;
    }
    if (text[i] === '"') return i + 1;
  }
  return fail("INVALID_JSON");
}

function scanValue(text: string, start: number): number {
  if (text[start] === '"') return scanString(text, start);
  if (text[start] === "{" || text[start] === "[") {
    const stack: string[] = [text[start] === "{" ? "}" : "]"];
    let insideString = false;
    for (let i = start + 1; i < text.length; i++) {
      const c = text[i];
      if (insideString) {
        if (c === "\\") i++;
        else if (c === '"') insideString = false;
      } else if (c === '"') {
        insideString = true;
      } else if (c === "{" || c === "[") {
        stack.push(c === "{" ? "}" : "]");
      } else if (c === "}" || c === "]") {
        if (stack.pop() !== c) fail("INVALID_JSON");
        if (stack.length === 0) return i + 1;
      }
    }
    return fail("INVALID_JSON");
  }
  let i = start;
  while (i < text.length && !/[\x20\t\n\r,}\]]/.test(text[i])) i++;
  if (i === start) fail("INVALID_JSON");
  return i;
}

function parseWireObject(wire: string): { value: Record<string, unknown>; raw: Map<string, string> } {
  if (wire.length > 65536) fail("OVERSIZE");
  let i = skipWhitespace(wire, 0);
  if (wire[i++] !== "{") fail("INVALID_JSON");
  const raw = new Map<string, string>();
  i = skipWhitespace(wire, i);
  while (wire[i] !== "}") {
    const endKey = scanString(wire, i);
    let key: string;
    try { key = JSON.parse(wire.slice(i, endKey)); }
    catch { return fail("INVALID_JSON"); }
    if (raw.has(key)) fail("DUPLICATE_FIELD");
    i = skipWhitespace(wire, endKey);
    if (wire[i++] !== ":") fail("INVALID_JSON");
    i = skipWhitespace(wire, i);
    const valueEnd = scanValue(wire, i);
    raw.set(key, wire.slice(i, valueEnd));
    i = skipWhitespace(wire, valueEnd);
    if (wire[i] === "}") break;
    if (wire[i++] !== ",") fail("INVALID_JSON");
    i = skipWhitespace(wire, i);
  }
  if (wire[i++] !== "}" || skipWhitespace(wire, i) !== wire.length) fail("INVALID_JSON");
  let value: unknown;
  try { value = JSON.parse(wire); }
  catch { return fail("INVALID_JSON"); }
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("INVALID_JSON");
  return { value: value as Record<string, unknown>, raw };
}

function expectedKeys(raw: Map<string, string>, keys: readonly string[]): void {
  if (raw.size !== keys.length || keys.some(key => !raw.has(key))) fail("INVALID_FIELDS");
}

/** Equivalent to Go json.Compact with escapeHTML on json.RawMessage. */
function compactRawJSON(raw: string): string {
  let result = "";
  let inString = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (inString && c === "\\") {
      result += c + (raw[++i] ?? "");
    } else if (c === '"') {
      inString = !inString;
      result += c;
    } else if (inString && /[<>&\u2028\u2029]/.test(c)) {
      result += "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0");
    } else if (inString || !/[\x20\t\n\r]/.test(c)) {
      result += c;
    }
  }
  return result;
}

function stringField(object: Record<string, unknown>, key: string, max: number): string {
  const value = object[key];
  if (!id(value, max)) fail("INVALID_FIELDS");
  return value;
}

function intField(object: Record<string, unknown>, key: string): number {
  const value = object[key];
  if (!positiveInt(value)) fail("INVALID_FIELDS");
  return value;
}

function signatureField(object: Record<string, unknown>): string {
  const value = object.signature;
  if (typeof value !== "string") fail("INVALID_SIGNATURE");
  return value;
}

function timestamps(issued: number, expires: number, now: number, skew: number, maxLifetime: number): void {
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(skew) || skew < 0 ||
      expires <= issued || expires - issued > maxLifetime) fail("INVALID_TIME");
  if (expires <= now) fail("EXPIRED");
  if (issued > now + skew) fail("FUTURE");
}

async function verifyEd25519(publicKey: string, signature: string, payload: string): Promise<void> {
  const keyBytes = b64url(publicKey, 32);
  const signatureBytes = b64url(signature, 64);
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("raw", keyBytes, "Ed25519", false, ["verify"]);
    const valid = await crypto.subtle.verify("Ed25519", key, signatureBytes, encoder.encode(payload));
    if (!valid) fail("INVALID_SIGNATURE");
  } catch (error) {
    if (error instanceof ProtocolError) throw error;
    fail("INVALID_SIGNATURE");
  }
}

function fieldJSON(object: Record<string, unknown>, fields: readonly string[]): string {
  return fields.map(key => quoted(key) + ":" +
    (typeof object[key] === "string" ? quoted(object[key]) : String(object[key]))).join(",");
}

export function canonicalAssertion(kind: "device" | "controller", wire: string): string {
  const { value, raw } = parseWireObject(wire);
  const fields = kind === "device"
    ? ["device_id", "generation", "agent_session_id", "issued_at", "expires_at", "nonce"]
    : ["device_id", "generation", "issued_at", "expires_at", "nonce"];
  expectedKeys(raw, [...fields, "signature"]);
  stringField(value, "device_id", 64);
  intField(value, "generation");
  if (kind === "device") stringField(value, "agent_session_id", 128);
  intField(value, "issued_at");
  intField(value, "expires_at");
  stringField(value, "nonce", 128);
  signatureField(value);
  return "{" + fieldJSON(value, fields) + "}";
}

export function canonicalCommand(wire: string): string {
  const { value, raw } = parseWireObject(wire);
  const fields = ["version", "request_id", "device_id", "session_id", "issued_at", "expires_at", "nonce", "tool"];
  expectedKeys(raw, [...fields, "arguments", "signature"]);
  if (value.version !== 1) fail("INVALID_VERSION");
  stringField(value, "request_id", 128);
  stringField(value, "device_id", 64);
  stringField(value, "session_id", 128);
  intField(value, "issued_at");
  intField(value, "expires_at");
  stringField(value, "nonce", 128);
  stringField(value, "tool", 128);
  signatureField(value);
  return "{" + fieldJSON(value, fields) + "," + quoted("arguments") + ":" +
    compactRawJSON(raw.get("arguments")!) + "}";
}

export async function verifyAssertion(
  kind: "device" | "controller",
  wire: string,
  authority: PairedAuthority,
): Promise<Record<string, unknown>> {
  const { value } = parseWireObject(wire);
  const canonical = canonicalAssertion(kind, wire);
  if (value.device_id !== authority.deviceId || value.generation !== authority.generation)
    fail("BINDING_MISMATCH");
  timestamps(value.issued_at as number, value.expires_at as number,
    authority.now, authority.clockSkewSeconds, 60);
  await verifyEd25519(authority.publicKey, value.signature as string, canonical);
  if (!await authority.replay.use(authority.deviceId, authority.generation,
    value.nonce as string, value.expires_at as number, authority.now)) fail("REPLAY");
  return value;
}

export async function verifySignedCommand(
  wire: string,
  authority: CommandAuthority,
): Promise<Record<string, unknown>> {
  const { value } = parseWireObject(wire);
  const canonical = canonicalCommand(wire);
  if (value.device_id !== authority.deviceId || value.session_id !== authority.agentSessionId)
    fail("BINDING_MISMATCH");
  timestamps(value.issued_at as number, value.expires_at as number,
    authority.now, authority.clockSkewSeconds, 300);
  await verifyEd25519(authority.publicKey, value.signature as string, canonical);
  if (!await authority.replay.use(authority.deviceId, authority.generation,
    value.nonce as string, value.expires_at as number, authority.now)) fail("REPLAY");
  return value;
}

export async function canonicalSha256(text: string): Promise<string> {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}
