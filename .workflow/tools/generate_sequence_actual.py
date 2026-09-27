#!/usr/bin/env python3
"""Project-local Go-aware static sequence generator.

Emits the Skill_Workflow actual-graph contract while delegating Go AST extraction
to go_sequence_ast.go. This file is intentionally under .workflow/tools so it
does not alter the application source digest it measures.
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
    nodes = sorted(extracted.get("nodes", []), key=lambda n: n["id"])
    edges = sorted(
        extracted.get("edges", []),
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
            "runtime_trace": False,
            "limitations": [
                "interface dynamic dispatch",
                "reflection",
                "callbacks/events",
                "cross-package selector resolution when the target leaf is ambiguous",
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
    out_json.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_mmd.write_text(
        "%% GENERATED FILE - DO NOT EDIT\n"
        f"%% SOURCE_DIGEST: {digest}\n"
        f"%% OBSERVED_HEAD: {head}\n"
        "%% GENERATED_BY: generate_sequence_actual.py\n"
        + render_mermaid(graph),
        encoding="utf-8",
    )
    print("OBSERVED_HEAD=" + head)
    print("SOURCE_DIGEST=" + digest)
    print("NODES=" + str(len(nodes)))
    print("EDGES=" + str(len(edges)))
    print("RESULT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
