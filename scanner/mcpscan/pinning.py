"""Phase 4: behavioral spec pinning and rug-pull detection."""
from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path

from . import engine
from .models import Finding, ToolDef

DEFAULT_BASELINE = ".mcp-scan/baseline.json"


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_tool(t: ToolDef) -> dict:
    return {
        "name": t.name,
        "hash": hashlib.sha256(_canon(t.to_dict()).encode()).hexdigest(),
        "description_hash": hashlib.sha256(t.description.encode()).hexdigest(),
        "schema_hash": hashlib.sha256(_canon(t.input_schema).encode()).hexdigest(),
        "description": t.description,   # kept so a diff can be shown later
        "inputSchema": t.input_schema,
    }


def snapshot(tools: list[ToolDef]) -> dict:
    out: dict = {}
    for t in tools:
        out.setdefault(t.server, {})[t.name] = hash_tool(t)
    return {"version": 1, "servers": out}


def load(path: str | Path) -> dict | None:
    p = Path(path)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def save(path: str | Path, snap: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(snap, indent=2, ensure_ascii=False), encoding="utf-8")


def side_by_side(old: str, new: str) -> str:
    diff = difflib.unified_diff(old.splitlines(), new.splitlines(), "pinned", "current", lineterm="", n=1)
    return "\n".join(diff)[:1500]


def diff(baseline: dict, current_tools: list[ToolDef]) -> list[Finding]:
    findings: list[Finding] = []
    cur = snapshot(current_tools)["servers"]
    base = baseline.get("servers", {})
    by_key = {(t.server, t.name): t for t in current_tools}

    for server, tools in cur.items():
        if server not in base:
            findings.append(Finding("T4-NEW-SERVER", 4, "New server not in baseline",
                                    f"Server '{server}' has no pinned baseline.", 0.4, server=server))
            continue
        for name, rec in tools.items():
            old = base[server].get(name)
            if old is None:
                findings.append(Finding("T4-NEW-TOOL", 4, "New tool added since baseline",
                                        f"Tool '{name}' was not present when pinned.", 0.5, server=server, tool=name))
                continue
            if old["hash"] == rec["hash"]:
                continue
            desc_changed = old["description_hash"] != rec["description_hash"]
            schema_changed = old["schema_hash"] != rec["schema_hash"]
            rescans = engine.scan_tool(by_key[(server, name)])
            worst = max((f.confidence for f in rescans), default=0.0)
            # a changed definition that also trips detectors is the rug-pull signature
            conf = 0.9 if worst >= 0.5 else (0.7 if desc_changed else 0.55)
            what = " and ".join(x for x, c in (("description", desc_changed), ("input schema", schema_changed)) if c)
            ev = side_by_side(old["description"], rec["description"]) if desc_changed else ""
            findings.append(Finding(
                "T4-RUG-PULL" if worst >= 0.5 else "T4-DRIFT", 4,
                "Possible rug pull: tool definition changed" if worst >= 0.5 else "Tool definition changed since baseline",
                f"The {what} of '{name}' differs from the pinned baseline"
                + (f"; the new version also triggers {len(rescans)} detector finding(s)." if worst >= 0.5 else "."),
                conf, server=server, tool=name, evidence=ev))
            findings.extend(rescans)
        for name in base[server]:
            if name not in tools:
                findings.append(Finding("T4-TOOL-REMOVED", 4, "Tool removed since baseline",
                                        f"Tool '{name}' is no longer offered.", 0.2, server=server, tool=name))
    return findings
