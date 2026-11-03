/**
 * Public edge router. Device authorization stays inside the per-device DO.
 * This Worker never accepts a local execution capability or a raw shell call.
 */
export { DeviceRelay } from "./device_relay";

export interface Env {
  DEVICE_RELAY: DurableObjectNamespace;
  PAIRING_BOOTSTRAP_SECRET?: string;
}

const devicePattern = /^dev_[A-Za-z0-9_-]{43}$/;

function secureHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const pathname = new URL(request.url).pathname;
    if (pathname === "/healthz" && request.method === "GET")
      return secureHeaders(new Response("ok\n", { status: 200 }));
    const match = /^\/v1\/devices\/([^/]+)\/([^?]+)$/.exec(pathname);
    if (!match || !devicePattern.test(match[1]))
      return secureHeaders(Response.json({ error: "not_found" }, { status: 404 }));
    if (!env.DEVICE_RELAY)
      return secureHeaders(Response.json({ error: "unavailable" }, { status: 503 }));
    // Namespace lookup is deterministic per full device ID, never a client-provided DO ID.
    const stub = env.DEVICE_RELAY.get(env.DEVICE_RELAY.idFromName(match[1]));
    return secureHeaders(await stub.fetch(request));
  },
};
