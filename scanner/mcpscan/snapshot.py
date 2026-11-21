"""Write reusable, no-clobber snapshots of MCP tool metadata."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .models import ToolDef


def save(path: Path, tools: list[ToolDef], servers: set[str]) -> None:
    buckets: dict[str, dict[str, list[dict]]] = {
        name: {"tools": []} for name in sorted(servers)
    }
    seen: set[tuple[str, str]] = set()
    for tool in sorted(tools, key=lambda item: (item.server, item.name)):
        key = (tool.server, tool.name)
        if not all(name.strip() for name in key) or not isinstance(tool.input_schema, dict):
            raise ValueError("snapshot contains an invalid tool definition")
        if key in seen:
            raise ValueError("snapshot contains duplicate server/tool identities")
        seen.add(key)
        buckets.setdefault(tool.server, {"tools": []})["tools"].append(tool.to_dict())
    if not buckets or any(not name.strip() for name in buckets):
        raise ValueError("snapshot has no servers or contains an empty server name")
    payload = json.dumps(buckets, indent=2, sort_keys=True, allow_nan=False) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def compare(before: list[ToolDef], after: list[ToolDef],
            before_servers: set[str], after_servers: set[str]) -> dict:
    """Compare scanner-relevant fields without echoing their contents."""
    def index(tools):
        result = {}
        for tool in tools:
            key = (tool.server, tool.name)
            if (key in result or not all(name.strip() for name in key)
                    or not isinstance(tool.input_schema, dict)):
                raise ValueError("invalid or duplicate tool identity or schema")
            result[key] = tool.to_dict()
        return result

    old, new = index(before), index(after)
    changes = []
    for server, tool in sorted(old.keys() | new.keys()):
        key = (server, tool)
        row = {"server": server, "tool": tool}
        if key not in old:
            changes.append({**row, "change": "added"})
        elif key not in new:
            changes.append({**row, "change": "removed"})
        else:
            fields = [field for field in ("description", "inputSchema")
                      if json.dumps(old[key][field], sort_keys=True, allow_nan=False)
                      != json.dumps(new[key][field], sort_keys=True, allow_nan=False)]
            if fields:
                changes.append({**row, "change": "modified", "fields": fields})
    added = sorted(after_servers - before_servers)
    removed = sorted(before_servers - after_servers)
    return {"changed": bool(changes or added or removed),
            "servers_added": added, "servers_removed": removed, "tools": changes}
