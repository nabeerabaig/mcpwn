"""Find and parse MCP client configs."""
from __future__ import annotations

import json
import os
import platform
import re
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


# Keep legacy discovery unchanged unless a client is selected explicitly.
CLIENTS = ("legacy", "gemini", "opencode", "hermes", "codex", "deepseek", "all")


def client_paths(client: str, project_dir: Path | None = None) -> list[Path]:
    project = (project_dir or Path.cwd()).resolve()
    home = Path.home()
    xdg = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
    codex = Path(os.environ.get("CODEX_HOME") or home / ".codex")
    hermes = Path(os.environ.get("HERMES_HOME") or home / ".hermes")
    opencode = Path(os.environ.get("OPENCODE_CONFIG_DIR") or xdg / "opencode")
    deepseek = Path(os.environ.get("DSH_HOME") or home / ".dsh")
    paths = {
        "legacy": candidate_config_paths(project),
        "gemini": [project / ".gemini/settings.json", home / ".gemini/settings.json"],
        "opencode": ([Path(os.environ["OPENCODE_CONFIG"])] if os.environ.get("OPENCODE_CONFIG") else [])
        + [base / name for base in (project, opencode) for name in ("opencode.json", "opencode.jsonc")],
        "hermes": [hermes / "config.yaml"],
        "codex": [project / ".codex/config.toml", codex / "config.toml"],
        "deepseek": [project / name for name in ("cordis.yml", "cordis.patch.yml")]
        + sorted(deepseek.glob("profiles/*/cordis.patch.yml")),
    }
    if client == "all":
        return list(dict.fromkeys(p for group in paths.values() for p in group))
    return paths[client]


class ConfigError(ValueError):
    pass


# Match quoted strings before comments so URLs and strings remain untouched.
_JSONC = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/|,(?=\s*[}\]])')


def _read(path: Path):
    text = path.read_text(encoding="utf-8-sig")
    suffix = path.suffix.lower()
    if suffix == ".toml":
        try:
            import tomllib
        except ImportError:
            raise ConfigError("TOML configs require Python 3.11 or newer") from None
        return tomllib.loads(text)
    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise ConfigError("YAML configs require PyYAML (python -m pip install PyYAML)") from None
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError:
            raise ConfigError("invalid YAML") from None
    if suffix == ".jsonc":
        text = _JSONC.sub(lambda m: m[0] if m[0].startswith('"') or m[0] == ',' else ' ', text)
        text = _JSONC.sub(lambda m: '' if m[0] == ',' else m[0], text)
    return json.loads(text)


def _normalize(name, cfg, path, notes):
    def skip(reason):
        notes.append(f"{path}: {name}: {reason}")

    if not isinstance(cfg, dict):
        return skip("expected a server object")
    if cfg.get("enabled") is False or cfg.get("disabled") is True:
        return
    kind = cfg.get("transport", cfg.get("type"))
    if kind not in (None, "local", "remote", "stdio", "http", "streamable-http", "streamableHttp", "sse"):
        return skip("unsupported transport")
    command, url = cfg.get("command"), cfg.get("httpUrl") or cfg.get("url")
    args = cfg.get("args", [])
    if isinstance(command, list):
        command, args = (command[0], command[1:]) if command else (None, [])
    if kind in ("remote", "http", "streamable-http", "streamableHttp", "sse"):
        command = None
    if kind in ("local", "stdio"):
        url = None
    if command and url:
        return skip("ambiguous command and URL")
    if command:
        env = cfg.get("environment", cfg.get("env", {}))
        if (not isinstance(command, str) or not isinstance(args, list)
                or not all(isinstance(arg, str) for arg in args) or not isinstance(env, dict)):
            return skip("invalid stdio command, arguments, or environment")
        if cfg.get("cwd") or cfg.get("env_vars"):
            return skip("client-specific cwd or environment inheritance is not supported")
        if any("{env:" in value or "{file:" in value or "${" in value
               for value in [command, *args, *map(str, env.values())]):
            return skip("client-specific interpolation is not supported")
        return ServerSpec(name=name, command=command, args=args, env=env, source=str(path))
    if url:
        headers = cfg.get("http_headers", cfg.get("headers", {}))
        if not isinstance(url, str) or not url.startswith(("http://", "https://")) or not isinstance(headers, dict):
            return skip("invalid HTTP URL or headers")
        if any(key in cfg and cfg[key] not in (None, False, "", {})
               for key in ("oauth", "oauthProviderType", "bearer_token_env_var", "env_http_headers")):
            return skip("client-managed authentication is not supported")
        if any("{env:" in value or "{file:" in value or "${" in value
               for value in [url, *map(str, headers.values())]):
            return skip("client-specific interpolation is not supported")
        transport = "sse" if kind == "sse" else "http"
        if path.name == "settings.json" and path.parent.name == ".gemini" and not cfg.get("httpUrl"):
            transport = "sse"  # Gemini distinguishes url (SSE) and httpUrl.
        if transport == "sse":
            return skip("legacy SSE is not supported")
        return ServerSpec(name=name, command="", transport=transport, url=url,
                          headers=headers, source=str(path))
    return skip("missing command or URL")


def _deepseek_plugins(entries, path, notes, depth=0):
    """Read literal MCP plugin entries; do not interpret patch selectors or scripts."""
    if not isinstance(entries, list) or depth > 32:
        notes.append(f"{path}: unsupported DeepSeek plugin list")
        return
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if "insert" in entry:
            yield from _deepseek_plugins(entry["insert"], path, notes, depth + 1)
        if entry.get("name") != "@deepseek-ai/dsh-mcp-client":
            continue
        cfg = entry.get("config")
        if not isinstance(cfg, dict) or not isinstance(cfg.get("serverName"), str) or not cfg["serverName"]:
            notes.append(f"{path}: DeepSeek MCP entry is missing config.serverName")
            continue
        if entry.get("enabled") is False or entry.get("disabled") is True:
            continue
        if cfg.get("transport") not in ("stdio", "streamable-http"):
            notes.append(f"{path}: unsupported or missing DeepSeek MCP transport")
            continue
        yield cfg["serverName"], cfg


def parse_config(path: Path, notes: list[str] | None = None) -> list[ServerSpec]:
    notes = [] if notes is None else notes
    try:
        data = _read(path)
    except ConfigError as exc:
        notes.append(f"{path}: {exc}")
        return []
    except (OSError, ValueError, RecursionError):
        notes.append(f"{path}: cannot read or parse config")
        return []
    if isinstance(data, list) and path.suffix.lower() in (".yaml", ".yml"):
        entries = list(_deepseek_plugins(data, path, notes))
        if len({name for name, _ in entries}) != len(entries):
            notes.append(f"{path}: duplicate DeepSeek MCP serverName")
            return []
        return [spec for name, cfg in entries if (spec := _normalize(name, cfg, path, notes)) is not None]
    if not isinstance(data, dict):
        notes.append(f"{path}: expected a config object")
        return []
    blocks = []
    for key in ("mcpServers", "servers", "mcp", "mcp_servers"):
        if isinstance(data.get(key), dict):
            blocks.append(data[key])
        elif key in data:
            notes.append(f"{path}: {key} must be an object")
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project in projects.values():
            if isinstance(project, dict) and isinstance(project.get("mcpServers"), dict):
                blocks.append(project["mcpServers"])
    specs = []
    seen = set()
    for block in blocks:
        for name, cfg in block.items():
            name = str(name)
            if name in seen:
                continue
            seen.add(name)
            spec = _normalize(name, cfg, path, notes)
            if spec is not None:
                specs.append(spec)
    return specs


def discover(paths: list[Path] | None = None, project_dir: Path | None = None, *,
             client: str = "legacy", notes: list[str] | None = None) -> list[ServerSpec]:
    notes = [] if notes is None else notes
    out = []
    seen = set()
    for path in paths if paths is not None else client_paths(client, project_dir):
        if not path.is_file():
            if paths is not None:
                notes.append(f"{path}: config file not found")
            continue
        for spec in parse_config(path, notes):
            key = (spec.name, spec.command, tuple(spec.args), spec.url)
            if key not in seen:
                seen.add(key)
                out.append(spec)
    return out
