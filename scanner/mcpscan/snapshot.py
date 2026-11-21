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
