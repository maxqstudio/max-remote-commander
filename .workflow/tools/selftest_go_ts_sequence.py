#!/usr/bin/env python3
"""Regression self-test for the project-local Go + TypeScript sequence extractor."""
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path


def load_generator():
    path = Path(__file__).with_name("generate_sequence_actual.py")
    spec = importlib.util.spec_from_file_location("maxrc_sequence_generator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load generate_sequence_actual.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    generator = load_generator()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "cloudflare" / "relay" / "src"
        src.mkdir(parents=True)

        (src / "index.ts").write_text(
            """export async function fetch(request: Request, env: Env): Promise<Response> {
  const relay = env.DEVICE_RELAY.getByName("device-test");
  return relay.fetch(request);
}

export default { fetch };
""",
            encoding="utf-8",
        )
        (src / "protocol.ts").write_text(
            """export async function verifySignedCommand(payload: unknown): Promise<void> {
  if (!payload) throw new Error("invalid");
}
""",
            encoding="utf-8",
        )
        (src / "device_relay.ts").write_text(
            """export class DeviceRelay {
  async fetch(request: Request): Promise<Response> {
    if (request.method === "POST") return this.queueCommand(request);
    if (request.method === "PUT") return this.submitResult(request);
    return this.waitResult(request);
  }

  async queueCommand(request: Request): Promise<Response> {
    await verifySignedCommand(await request.json());
    await this.deliverHead();
    return new Response("queued");
  }

  async deliverHead(): Promise<void> {}

  async submitResult(request: Request): Promise<Response> {
    return new Response("result");
  }

  async waitResult(request: Request): Promise<Response> {
    return new Response("wait");
  }
}
""",
            encoding="utf-8",
        )

        nodes, edges = generator.collect_ts_symbols(root)
        node_ids = {str(node["id"]) for node in nodes}
        edge_ids = {(str(edge["from"]), str(edge["to"])) for edge in edges}

        expected_nodes = {
            "cloudflare/relay/src/index.ts::fetch",
            "cloudflare/relay/src/protocol.ts::verifySignedCommand",
            "cloudflare/relay/src/device_relay.ts::DeviceRelay.fetch",
            "cloudflare/relay/src/device_relay.ts::DeviceRelay.queueCommand",
            "cloudflare/relay/src/device_relay.ts::DeviceRelay.deliverHead",
            "cloudflare/relay/src/device_relay.ts::DeviceRelay.submitResult",
            "cloudflare/relay/src/device_relay.ts::DeviceRelay.waitResult",
        }
        expected_edges = {
            ("cloudflare/relay/src/index.ts::fetch", "cloudflare/relay/src/device_relay.ts::DeviceRelay.fetch"),
            ("cloudflare/relay/src/device_relay.ts::DeviceRelay.fetch", "cloudflare/relay/src/device_relay.ts::DeviceRelay.queueCommand"),
            ("cloudflare/relay/src/device_relay.ts::DeviceRelay.fetch", "cloudflare/relay/src/device_relay.ts::DeviceRelay.submitResult"),
            ("cloudflare/relay/src/device_relay.ts::DeviceRelay.fetch", "cloudflare/relay/src/device_relay.ts::DeviceRelay.waitResult"),
            ("cloudflare/relay/src/device_relay.ts::DeviceRelay.queueCommand", "cloudflare/relay/src/protocol.ts::verifySignedCommand"),
            ("cloudflare/relay/src/device_relay.ts::DeviceRelay.queueCommand", "cloudflare/relay/src/device_relay.ts::DeviceRelay.deliverHead"),
        }

        missing_nodes = expected_nodes - node_ids
        missing_edges = expected_edges - edge_ids
        if missing_nodes:
            raise RuntimeError("missing TypeScript nodes: " + ", ".join(sorted(missing_nodes)))
        if missing_edges:
            raise RuntimeError("missing TypeScript edges: " + ", ".join(f"{a}->{b}" for a, b in sorted(missing_edges)))

    print("GO_TS_SEQUENCE_EXTRACTOR_SELFTEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
