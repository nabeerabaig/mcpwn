"""Find and parse MCP client configs."""
from __future__ import annotations

import json
import os
import platform
from pathlib import Path

from .models import ServerSpec


def candidate_config_paths(project_dir: Path | None = None) -> list[Path]:
    home = Path.home()
    proj = project_dir or Path.cwd()
    paths = [
        proj / ".mcp.json",
        proj / ".cursor" / "mcp.json",
        proj / ".vscode" / "mcp.json",
        proj / ".windsurf" / "mcp_config.json",
        home / ".claude.json",
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
    ]
    system = platform.system()
    if system == "Darwin":
        paths.append(home / "Library/Application Support/Claude/claude_desktop_config.json")
    elif system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            paths.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
    else:
        paths.append(home / ".config/Claude/claude_desktop_config.json")
    return paths


def parse_config(path: Path) -> list[ServerSpec]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    blocks = []
    if isinstance(data, dict):
        for key in ("mcpServers", "servers"):
            if isinstance(data.get(key), dict):
                blocks.append(data[key])
        projects = data.get("projects")  # ~/.claude.json per-project servers
        if isinstance(projects, dict):
            for p in projects.values():
                if isinstance(p, dict) and isinstance(p.get("mcpServers"), dict):
                    blocks.append(p["mcpServers"])
    specs: list[ServerSpec] = []
    seen = set()
    for block in blocks:
        for name, cfg in block.items():
            if not isinstance(cfg, dict) or name in seen:
                continue
            seen.add(name)
            if cfg.get("command"):
                specs.append(ServerSpec(name=name, command=str(cfg["command"]), args=list(cfg.get("args") or []),
                                        env=dict(cfg.get("env") or {}), source=str(path)))
            elif cfg.get("url"):
                specs.append(ServerSpec(name=name, command="", transport=str(cfg.get("type") or "http"),
                                        url=str(cfg["url"]), headers=dict(cfg.get("headers") or {}), source=str(path)))
    return specs


def discover(paths: list[Path] | None = None, project_dir: Path | None = None) -> list[ServerSpec]:
    out: list[ServerSpec] = []
    seen = set()
    for p in paths or candidate_config_paths(project_dir):
        if p.is_file():
            for s in parse_config(p):
                key = (s.name, s.command, tuple(map(str, s.args)), s.url)
                if key not in seen:
                    seen.add(key)
                    out.append(s)
    return out
