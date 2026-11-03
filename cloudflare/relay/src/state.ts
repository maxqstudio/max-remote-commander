/**
 * SQLite-backed, per-device relay state. The containing Durable Object is
 * responsible for cryptographic verification and HTTP/session authorization.
 * No method here grants remote execution or produces a bearer session.
 */

export interface SqlCursor<T> extends Iterable<T> {}
export interface SqlEngine {
  exec<T extends Record<string, unknown>>(query: string, ...params: (string | number | null)[]): SqlCursor<T>;
}
export interface DurableSql {
  sql: SqlEngine;
  transactionSync<T>(callback: () => T): T;
}

export interface Pairing {
  deviceId: string;
  generation: number;
  devicePublicKey: string;
  controllerPublicKey: string;
}

export interface VerifiedCommandInput {
  requestId: string;
  deviceId: string;
  generation: number;
  agentSessionId: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  envelopeJSON: string;
}

export interface StoredCommand {
  requestId: string;
  envelopeJSON: string;
  expiresAt: number;
}

export interface StoredResult {
  requestId: string;
  payload: string;
  expiresAt: number;
}

const idPattern = /^[A-Za-z0-9._:-]+$/;
const MAX_QUEUE = 128;
const MAX_RESULTS = 256;
const MAX_ENVELOPE_BYTES = 65536;
const MAX_RESULT_BYTES = 65536;
const RESULT_TTL_SECONDS = 600;
const MAX_SESSION_TTL_SECONDS = 900;
const utf8Bytes = (text: string) => new TextEncoder().encode(text).byteLength;

export class DurableStateError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "DurableStateError";
    this.code = code;
  }
}

function reject(code: string): never { throw new DurableStateError(code); }

function checkId(value: string, maximum: number): void {
  if (!value || value.length > maximum || !idPattern.test(value)) reject("INVALID_IDENTIFIER");
}

function one<T extends Record<string, unknown>>(rows: Iterable<T>): T | null {
  for (const row of rows) return row;
  return null;
}

function safeInt(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

export class DurableRelayState {
  private readonly storage: DurableSql;
  private activeSession: string | null = null;
  private activeSessionExpiresAt = 0;

  constructor(storage: DurableSql) {
    this.storage = storage;
    const sql = storage.sql;
    sql.exec(`CREATE TABLE IF NOT EXISTS trust (
      slot INTEGER PRIMARY KEY CHECK (slot = 1),
      device_id TEXT,
      generation INTEGER NOT NULL,
      device_public_key TEXT,
      controller_public_key TEXT
    )`);
    sql.exec(`INSERT OR IGNORE INTO trust (slot, device_id, generation, device_public_key, controller_public_key)
              VALUES (1, NULL, 0, NULL, NULL)`);
    sql.exec(`CREATE TABLE IF NOT EXISTS queue (
      position INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id TEXT NOT NULL UNIQUE,
      generation INTEGER NOT NULL,
      agent_session_id TEXT NOT NULL,
      envelope_json TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      leased_until INTEGER NOT NULL DEFAULT 0
    )`);
    sql.exec(`CREATE TABLE IF NOT EXISTS result (
      request_id TEXT PRIMARY KEY,
      generation INTEGER NOT NULL,
      payload TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    )`);
    sql.exec(`CREATE TABLE IF NOT EXISTS replay (
      domain TEXT NOT NULL,
      generation INTEGER NOT NULL,
      nonce TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      PRIMARY KEY (domain, generation, nonce)
    )`);
  }

  pairing(): Pairing | null {
    const row = one(this.storage.sql.exec<{device_id:string|null;generation:number;
      device_public_key:string|null;controller_public_key:string|null}>(
      "SELECT device_id, generation, device_public_key, controller_public_key FROM trust WHERE slot = 1"));
    if (!row?.device_id || !row.device_public_key || !row.controller_public_key) return null;
    return {
      deviceId: row.device_id,
      generation: row.generation,
      devicePublicKey: row.device_public_key,
      controllerPublicKey: row.controller_public_key,
    };
  }

  /**
   * Internal bootstrap commit ONLY after pairing code and device-key identity
   * have been independently verified by the Durable Object's pairing handler.
   * Never expose this as a public HTTP operation.
   */
  installVerifiedPairing(deviceId: string, devicePublicKey: string, controllerPublicKey: string): Pairing {
    checkId(deviceId, 64);
    if (!/^[A-Za-z0-9_-]{43}$/.test(devicePublicKey) ||
        !/^[A-Za-z0-9_-]{43}$/.test(controllerPublicKey)) reject("INVALID_KEY");
    this.storage.transactionSync(() => {
      const active = this.pairing();
      if (active) reject("ALREADY_PAIRED");
      this.storage.sql.exec(
        "UPDATE trust SET device_id=?, generation=generation+1, device_public_key=?, controller_public_key=? WHERE slot=1",
        deviceId, devicePublicKey, controllerPublicKey);
      this.storage.sql.exec("DELETE FROM queue");
      this.storage.sql.exec("DELETE FROM result");
      this.storage.sql.exec("DELETE FROM replay");
    });
    this.activeSession = null;
    this.activeSessionExpiresAt = 0;
    return this.pairing()!;
  }

  /**
   * Internal only, after successful signed device assertion and durable replay
   * claim. Invalidates ephemeral authority and prunes queued stale sessions.
   */
  activateAuthenticatedAgentSession(deviceId: string, generation: number,
    agentSessionId: string, nonce: string, assertionExpiresAt: number,
    now: number, sessionExpiresAt: number): void {
    checkId(agentSessionId, 128);
    checkId(nonce, 128);
    if (!safeInt(now) || !safeInt(assertionExpiresAt) || assertionExpiresAt <= now ||
        !safeInt(sessionExpiresAt) || sessionExpiresAt <= now ||
        sessionExpiresAt - now > MAX_SESSION_TTL_SECONDS)
      reject("INVALID_TIME");
    this.storage.transactionSync(() => {
      this.requirePairing(deviceId, generation);
      this.storage.sql.exec("DELETE FROM replay WHERE expires_at <= ?", now);
      const repeated = one(this.storage.sql.exec<{nonce:string}>(
        "SELECT nonce FROM replay WHERE domain='device' AND generation=? AND nonce=?",
        generation, nonce));
      if (repeated) reject("REPLAY");
      this.storage.sql.exec(
        "INSERT INTO replay (domain,generation,nonce,expires_at) VALUES ('device',?,?,?)",
        generation, nonce, assertionExpiresAt);
      this.storage.sql.exec(
        "DELETE FROM queue WHERE agent_session_id <> ? OR expires_at <= ? OR generation <> ?",
        agentSessionId, now, generation);
      this.storage.sql.exec("DELETE FROM result WHERE expires_at <= ?", now);
    });
    this.activeSession = agentSessionId;
    this.activeSessionExpiresAt = sessionExpiresAt;
  }

  /**
   * Claim a nonce and insert the verified, session-bound command atomically.
   * Call ONLY after verifySignedCommandSignature succeeds using pairing().
   */
  commitVerifiedCommand(command: VerifiedCommandInput, now: number): void {
    checkId(command.requestId, 128);
    checkId(command.nonce, 128);
    if (!safeInt(now) || !safeInt(command.issuedAt) || !safeInt(command.expiresAt) ||
        command.expiresAt <= now || command.expiresAt <= command.issuedAt ||
        command.expiresAt - command.issuedAt > 300 || command.issuedAt > now ||
        !Number.isSafeInteger(command.generation) || command.generation < 1 ||
        utf8Bytes(command.envelopeJSON) > MAX_ENVELOPE_BYTES) reject("INVALID_COMMAND");
    if (this.activeSession === null || command.agentSessionId !== this.activeSession)
      reject("SESSION_MISMATCH");
    if (now >= this.activeSessionExpiresAt) reject("SESSION_EXPIRED");
    let decoded: Record<string, unknown>;
    try { decoded = JSON.parse(command.envelopeJSON); }
    catch { return reject("INVALID_COMMAND"); }
    if (decoded.request_id !== command.requestId || decoded.device_id !== command.deviceId ||
        decoded.session_id !== command.agentSessionId || decoded.nonce !== command.nonce ||
        decoded.issued_at !== command.issuedAt || decoded.expires_at !== command.expiresAt)
      reject("ENVELOPE_MISMATCH");
    this.storage.transactionSync(() => {
      this.requirePairing(command.deviceId, command.generation);
      if (this.activeSession !== command.agentSessionId) reject("SESSION_MISMATCH");
      this.storage.sql.exec("DELETE FROM replay WHERE expires_at <= ?", now);
      this.storage.sql.exec("DELETE FROM queue WHERE expires_at <= ?", now);
      this.storage.sql.exec("DELETE FROM result WHERE expires_at <= ?", now);
      const count = one(this.storage.sql.exec<{n:number}>("SELECT COUNT(*) AS n FROM queue"));
      if (!count || count.n >= MAX_QUEUE) reject("QUEUE_FULL");
      const duplicate = one(this.storage.sql.exec<{nonce:string}>(
        "SELECT nonce FROM replay WHERE domain='command' AND generation=? AND nonce=?",
        command.generation, command.nonce));
      if (duplicate) reject("REPLAY");
      const repeatedRequest = one(this.storage.sql.exec<{request_id:string}>(
        "SELECT request_id FROM queue WHERE request_id=?", command.requestId));
      if (repeatedRequest) reject("DUPLICATE_REQUEST");
      // Completed request IDs remain reserved for the result retention window.
      // Otherwise a fresh nonce could requeue already-completed work and
      // collide with the durable result's unique request_id on completion.
      const completedRequest = one(this.storage.sql.exec<{request_id:string}>(
        "SELECT request_id FROM result WHERE request_id=?", command.requestId));
      if (completedRequest) reject("DUPLICATE_REQUEST");
      this.storage.sql.exec(
        "INSERT INTO replay (domain,generation,nonce,expires_at) VALUES ('command',?,?,?)",
        command.generation, command.nonce, command.expiresAt);
      this.storage.sql.exec(
        "INSERT INTO queue (request_id,generation,agent_session_id,envelope_json,expires_at) VALUES (?,?,?,?,?)",
        command.requestId, command.generation, command.agentSessionId,
        command.envelopeJSON, command.expiresAt);
    });
  }

  /** Use for signed device/controller assertion replay within the same SQL commit as any associated mutation. */
  claimAssertionNonce(domain: "device" | "controller", deviceId: string, generation: number,
    nonce: string, expiresAt: number, now: number): void {
    checkId(nonce, 128);
    if (!safeInt(now) || !safeInt(expiresAt) || expiresAt <= now) reject("INVALID_TIME");
    this.storage.transactionSync(() => {
      this.requirePairing(deviceId, generation);
      this.storage.sql.exec("DELETE FROM replay WHERE expires_at <= ?", now);
      const duplicate = one(this.storage.sql.exec<{nonce:string}>(
        "SELECT nonce FROM replay WHERE domain=? AND generation=? AND nonce=?",
        domain, generation, nonce));
      if (duplicate) reject("REPLAY");
      this.storage.sql.exec("INSERT INTO replay (domain,generation,nonce,expires_at) VALUES (?,?,?,?)",
        domain, generation, nonce, expiresAt);
    });
  }

  /** Lease only the FIFO head. A later request cannot bypass an outstanding lease. */
  leaseHead(deviceId: string, generation: number, agentSessionId: string,
    now: number, leaseSeconds: number): StoredCommand | null {
    if (!safeInt(now) || !safeInt(leaseSeconds) || leaseSeconds > 60) reject("INVALID_TIME");
    if (agentSessionId !== this.activeSession) reject("SESSION_MISMATCH");
    if (now >= this.activeSessionExpiresAt) reject("SESSION_EXPIRED");
    return this.storage.transactionSync(() => {
      this.requirePairing(deviceId, generation);
      this.storage.sql.exec("DELETE FROM queue WHERE expires_at <= ?", now);
      const head = one(this.storage.sql.exec<{request_id:string;envelope_json:string;expires_at:number;leased_until:number;agent_session_id:string;generation:number}>(
        "SELECT request_id,envelope_json,expires_at,leased_until,agent_session_id,generation FROM queue ORDER BY position ASC LIMIT 1"));
      if (!head) return null;
      if (head.agent_session_id !== agentSessionId || head.generation !== generation) reject("STALE_QUEUE");
      if (head.leased_until > now) return null;
      this.storage.sql.exec("UPDATE queue SET leased_until=? WHERE request_id=?",
        Math.min(now + leaseSeconds, head.expires_at), head.request_id);
      return {requestId: head.request_id, envelopeJSON: head.envelope_json, expiresAt: head.expires_at};
    });
  }

  completeResult(deviceId: string, generation: number, agentSessionId: string,
    requestId: string, payload: string, now: number): void {
    checkId(requestId, 128);
    if (typeof payload !== "string" || utf8Bytes(payload) > MAX_RESULT_BYTES || !safeInt(now) ||
        agentSessionId !== this.activeSession) reject("INVALID_RESULT");
    if (now >= this.activeSessionExpiresAt) reject("SESSION_EXPIRED");
    try { JSON.parse(payload); } catch { return reject("INVALID_RESULT"); }
    this.storage.transactionSync(() => {
      this.requirePairing(deviceId, generation);
      const command = one(this.storage.sql.exec<{request_id:string;agent_session_id:string;generation:number}>(
        "SELECT request_id,agent_session_id,generation FROM queue WHERE request_id=?", requestId));
      if (!command || command.agent_session_id !== agentSessionId || command.generation !== generation)
        reject("UNKNOWN_REQUEST");
      this.storage.sql.exec("DELETE FROM queue WHERE request_id=?", requestId);
      this.storage.sql.exec(
        "INSERT INTO result (request_id,generation,payload,expires_at) VALUES (?,?,?,?)",
        requestId, generation, payload, now + RESULT_TTL_SECONDS);
      // Keep result retention bounded even when expiry has not elapsed.
      this.storage.sql.exec("DELETE FROM result WHERE expires_at <= ?", now);
      this.storage.sql.exec(`DELETE FROM result WHERE request_id IN (
        SELECT request_id FROM result ORDER BY rowid DESC LIMIT -1 OFFSET ${MAX_RESULTS}
      )`);
    });
  }

  /** Data lookup only: the HTTP handler must authenticate owning controller session. */
  resultForAuthorizedController(deviceId: string, generation: number,
    requestId: string, now: number): StoredResult | null {
    this.requirePairing(deviceId, generation);
    const row = one(this.storage.sql.exec<{request_id:string;payload:string;expires_at:number;generation:number}>(
      "SELECT request_id,payload,expires_at,generation FROM result WHERE request_id=?", requestId));
    if (!row || row.expires_at <= now || row.generation !== generation) return null;
    return {requestId: row.request_id, payload: row.payload, expiresAt: row.expires_at};
  }

  revokeAuthenticatedDevice(deviceId: string, generation: number): void {
    this.storage.transactionSync(() => {
      this.requirePairing(deviceId, generation);
      this.storage.sql.exec(
        "UPDATE trust SET device_id=NULL, device_public_key=NULL, controller_public_key=NULL WHERE slot=1");
      this.storage.sql.exec("DELETE FROM queue");
      this.storage.sql.exec("DELETE FROM result");
      this.storage.sql.exec("DELETE FROM replay");
    });
    this.activeSession = null;
    this.activeSessionExpiresAt = 0;
  }

  private requirePairing(deviceId: string, generation: number): Pairing {
    const pairing = this.pairing();
    if (!pairing || pairing.deviceId !== deviceId || pairing.generation !== generation)
      reject("PAIRING_MISMATCH");
    return pairing;
  }
}
