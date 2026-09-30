#!/usr/bin/env python3
"""Project-local Go-aware static sequence generator.

Compatible with Skill_Workflow 024e2ea458b25ad9dfb401d3fdeaa994a4cbe1b8.
It preserves the actual-graph contract while extending extraction to Go through
go_sequence_ast.go. This project-specific extension remains under .workflow/tools
so it does not alter the application source digest it measures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import defaultdict, deque
from pathlib import Path

SOURCE_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".kts",
    ".cs", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".rs", ".go",
    ".swift", ".m", ".mm", ".php", ".rb", ".scala", ".sh", ".ps1", ".sql",
    ".proto", ".graphql", ".gql", ".xml", ".gradle",
}
EXCLUDED = {
    ".git", ".workflow", ".idea", ".vscode", ".venv", "venv", "node_modules",
    "dist", "build", "coverage", "vendor", "__pycache__",
}

TS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
TS_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"


def mask_ts_noncode(text: str) -> str:
    """Mask JS/TS strings and comments while preserving offsets/newlines."""
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i + 2)
            if j < 0:
                j = n
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                j = n - 2
            end = min(n, j + 2)
            for k in range(i, end):
                if out[k] != "\n":
                    out[k] = " "
            i = end
            continue
        if text[i] in {'"', "'", "`"}:
            quote = text[i]
            out[i] = " "
            i += 1
            while i < n:
                ch = text[i]
                if ch == "\\":
                    out[i] = " "
                    if i + 1 < n:
                        if out[i + 1] != "\n":
                            out[i + 1] = " "
                        i += 2
                    else:
                        i += 1
                    continue
                if ch == quote:
                    out[i] = " "
                    i += 1
                    break
                if ch != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def brace_depths(masked: str) -> list[int]:
    depth = 0
    result = [0] * (len(masked) + 1)
    for i, ch in enumerate(masked):
        result[i] = depth
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
    result[len(masked)] = depth
    return result


def matching_brace(masked: str, start: int) -> int:
    if start < 0 or start >= len(masked) or masked[start] != "{":
        return -1
    depth = 0
    for i in range(start, len(masked)):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def collect_ts_symbols(root: Path) -> tuple[list[dict], list[dict]]:
    """Narrow deterministic JS/TS symbol/call extractor for governed flows."""
    nodes: list[dict] = []
    bodies: dict[str, tuple[str, str | None]] = {}

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TS_EXTENSIONS:
            continue
        rel = path.relative_to(root)
        if any(part in EXCLUDED for part in rel.parts):
            continue
        rel_text = rel.as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        masked = mask_ts_noncode(text)
        depths = brace_depths(masked)

        function_re = re.compile(
            rf"(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+({TS_IDENT})"
            rf"\s*\([^)]*\)\s*(?::\s*[^{{]+)?\s*{{"
        )
        for match in function_re.finditer(masked):
            if depths[match.start()] != 0:
                continue
            open_brace = masked.find("{", match.start(), match.end())
            close_brace = matching_brace(masked, open_brace)
            if close_brace < 0:
                continue
            name = match.group(1)
            symbol = f"{rel_text}::{name}"
            nodes.append({
                "id": symbol,
                "label": symbol,
                "locator": symbol,
                "kind": "function",
                "language": "JavaScript/TypeScript",
            })
            bodies[symbol] = (masked[open_brace + 1:close_brace], None)

        class_re = re.compile(rf"(?:export\s+)?(?:default\s+)?class\s+({TS_IDENT})[^{{]*{{")
        method_re = re.compile(
            rf"(?:(?:public|private|protected|static|async|readonly|override|abstract)\s+)*"
            rf"({TS_IDENT})\s*\([^)]*\)\s*(?::\s*[^{{]+)?\s*{{"
        )
        for class_match in class_re.finditer(masked):
            if depths[class_match.start()] != 0:
                continue
            class_name = class_match.group(1)
            class_open = masked.find("{", class_match.start(), class_match.end())
            class_close = matching_brace(masked, class_open)
            if class_close < 0:
                continue
            class_body = masked[class_open + 1:class_close]
            class_depths = brace_depths(class_body)
            for method_match in method_re.finditer(class_body):
                if class_depths[method_match.start()] != 0:
                    continue
                method_name = method_match.group(1)
                method_open = class_body.find("{", method_match.start(), method_match.end())
                method_close = matching_brace(class_body, method_open)
                if method_close < 0:
                    continue
                symbol = f"{rel_text}::{class_name}.{method_name}"
                nodes.append({
                    "id": symbol,
                    "label": symbol,
                    "locator": symbol,
                    "kind": "method",
                    "language": "JavaScript/TypeScript",
                })
                bodies[symbol] = (
                    class_body[method_open + 1:method_close],
                    class_name,
                )

    unique_nodes: dict[str, dict] = {}
    for node in nodes:
        unique_nodes.setdefault(str(node["id"]), node)
    nodes = sorted(unique_nodes.values(), key=lambda item: str(item["id"]))

    leaf_map: dict[str, list[str]] = defaultdict(list)
    class_method_map: dict[tuple[str, str], str] = {}
    for node in nodes:
        symbol = str(node["id"])
        tail = symbol.split("::", 1)[-1]
        leaf = tail.rsplit(".", 1)[-1]
        leaf_map[leaf].append(symbol)
        if "." in tail:
            class_name, method_name = tail.rsplit(".", 1)
            class_method_map[(class_name, method_name)] = symbol

    edges: list[dict] = []
    member_call = re.compile(rf"\b({TS_IDENT})\.({TS_IDENT})\s*\(")
    direct_call = re.compile(rf"(?<![.\w$])({TS_IDENT})\s*\(")
    keywords = {"if", "for", "while", "switch", "catch", "return", "new", "typeof"}

    for caller, (body, class_name) in bodies.items():
        emitted: set[tuple[str, str]] = set()
        for match in member_call.finditer(body):
            owner, method = match.groups()
            target = None
            if owner == "this" and class_name:
                target = class_method_map.get((class_name, method))
            else:
                candidates = [x for x in leaf_map.get(method, []) if x != caller]
                if len(candidates) == 1:
                    target = candidates[0]
            if target and (caller, target) not in emitted:
                emitted.add((caller, target))
                edges.append({
                    "from": caller,
                    "to": target,
                    "action": f"call {method}",
                    "evidence": "STATIC",
                    "resolver": "ts_symbol_scan",
                })

        member_spans = [(m.start(2), m.end(2)) for m in member_call.finditer(body)]
        for match in direct_call.finditer(body):
            name = match.group(1)
            if name in keywords:
                continue
            if any(start <= match.start(1) < end for start, end in member_spans):
                continue
            candidates = [x for x in leaf_map.get(name, []) if x != caller]
            if len(candidates) == 1:
                target = candidates[0]
                if (caller, target) not in emitted:
                    emitted.add((caller, target))
                    edges.append({
                        "from": caller,
                        "to": target,
                        "action": f"call {name}",
                        "evidence": "STATIC",
                        "resolver": "ts_symbol_scan",
                    })

    return nodes, sorted(
        edges,
        key=lambda edge: (str(edge["from"]), str(edge["to"]), str(edge["action"])),
    )


def source_files(root: Path) -> list[Path]:
    result = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        rel = path.relative_to(root)
        if any(part in EXCLUDED for part in rel.parts):
            continue
        result.append(path)
    return sorted(result, key=lambda p: p.relative_to(root).as_posix())


def compute_source_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in source_files(root):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def git_head(root: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()


def sanitize_alias(value: str, index: int) -> str:
    base = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not base or base[0].isdigit():
        base = "p_" + base
    return f"{base}_{index}"


def render_mermaid(graph: dict) -> str:
    aliases = {}
    lines = ["sequenceDiagram"]
    for i, node in enumerate(graph.get("nodes", [])):
        node_id = str(node.get("id", "")).strip()
        if not node_id:
            continue
        alias = sanitize_alias(node_id, i)
        aliases[node_id] = alias
        label = str(node.get("label") or node.get("locator") or node_id)
        label = label.replace("\n", " ").replace('"', "'")
        prefix = "actor" if str(node.get("kind", "")).lower() == "actor" else "participant"
        lines.append(f"    {prefix} {alias} as {label}")
    for edge in graph.get("edges", []):
        src = str(edge.get("from", "")).strip()
        dst = str(edge.get("to", "")).strip()
        if src not in aliases or dst not in aliases:
            continue
        action = str(edge.get("action", "call")).replace("\n", " ")
        evidence = str(edge.get("evidence", "")).strip()
        requirement = str(edge.get("requirement", "")).strip()
        suffix = [x for x in (requirement, evidence) if x]
        if suffix:
            action += " [" + ",".join(suffix) + "]"
        lines.append(f"    {aliases[src]}->>{aliases[dst]}: {action}")
    return "\n".join(lines) + "\n"


def filter_reachable(nodes: list[dict], edges: list[dict], entries: list[str], depth: int):
    if not entries:
        return nodes, edges
    adjacency = defaultdict(list)
    for edge in edges:
        adjacency[str(edge["from"])].append(str(edge["to"]))
    keep = set(entries)
    queue = deque((entry, 0) for entry in entries)
    while queue:
        node, d = queue.popleft()
        if d >= depth:
            continue
        for nxt in adjacency.get(node, []):
            if nxt not in keep:
                keep.add(nxt)
                queue.append((nxt, d + 1))
    return (
        [n for n in nodes if n["id"] in keep],
        [e for e in edges if e["from"] in keep and e["to"] in keep],
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--output-json", required=True)
    ap.add_argument("--output-mermaid", required=True)
    ap.add_argument("--entry", action="append", default=[])
    ap.add_argument("--max-depth", type=int, default=12)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    helper = Path(__file__).with_name("go_sequence_ast.go")
    proc = subprocess.run(
        ["go", "run", str(helper), "--root", str(root)],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        print(proc.stderr, end="")
        print("FAIL GO_SEQUENCE_AST")
        return proc.returncode

    extracted = json.loads(proc.stdout)
    go_nodes = extracted.get("nodes", [])
    go_edges = extracted.get("edges", [])
    ts_nodes, ts_edges = collect_ts_symbols(root)

    node_map: dict[str, dict] = {}
    for node in [*go_nodes, *ts_nodes]:
        node_id = str(node.get("id", ""))
        if node_id:
            node_map.setdefault(node_id, node)
    nodes = sorted(node_map.values(), key=lambda n: str(n["id"]))

    edge_map: dict[tuple[str, str, str, str], dict] = {}
    for edge in [*go_edges, *ts_edges]:
        key = (
            str(edge.get("from", "")),
            str(edge.get("to", "")),
            str(edge.get("action", "")),
            str(edge.get("resolver", "")),
        )
        edge_map.setdefault(key, edge)
    edges = sorted(
        edge_map.values(),
        key=lambda e: (str(e.get("from")), str(e.get("to")), str(e.get("action"))),
    )
    known = {n["id"] for n in nodes}
    missing = [entry for entry in args.entry if entry not in known]
    if missing:
        for entry in missing:
            print("FAIL ENTRY_NOT_RESOLVED:" + entry)
        return 1

    nodes, edges = filter_reachable(nodes, edges, args.entry, args.max_depth)
    head = git_head(root)
    digest = compute_source_digest(root)
    graph = {
        "schema_version": 1,
        "generated": True,
        "generated_by": "generate_sequence_actual.py",
        "observed_head": head,
        "source_digest": digest,
        "entries": args.entry,
        "nodes": nodes,
        "edges": edges,
        "coverage": {
            "go_ast": True,
            "typescript_symbol_scan": True,
            "runtime_trace": False,
            "limitations": [
                "interface dynamic dispatch",
                "reflection",
                "callbacks/events",
                "cross-package selector resolution when the target leaf is ambiguous",
                "TypeScript overloads/dynamic dispatch and computed property calls",
            ],
        },
    }

    out_json = Path(args.output_json)
    if not out_json.is_absolute():
        out_json = root / out_json
    out_mmd = Path(args.output_mermaid)
    if not out_mmd.is_absolute():
        out_mmd = root / out_mmd
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_mmd.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_bytes((json.dumps(graph, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    out_mmd.write_bytes((
        "%% GENERATED FILE - DO NOT EDIT\n"
        f"%% SOURCE_DIGEST: {digest}\n"
        f"%% OBSERVED_HEAD: {head}\n"
        "%% GENERATED_BY: generate_sequence_actual.py\n"
        + render_mermaid(graph)
    ).encode("utf-8"))
    print("OBSERVED_HEAD=" + head)
    print("SOURCE_DIGEST=" + digest)
    print("NODES=" + str(len(nodes)))
    print("EDGES=" + str(len(edges)))
    print("RESULT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
