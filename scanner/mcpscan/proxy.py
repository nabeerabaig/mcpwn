"""Phase 4: stdio proxy between an MCP client and a real server.

Usage in a client config:
  "command": "python3", "args": [".../run.py", "proxy", "--server-name", "x", "--", "real-cmd", "arg"]

It relays JSON-RPC unchanged, and inspects every tools/list response: scans it, diffs it against the
pinned baseline, logs alerts to stderr and (optionally) a webhook. With --block-critical, a tools/list
response containing critical findings is replaced by an error so the client never sees the tools.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.request

from . import engine, pinning
from .models import Finding, SEVERITY_ORDER, ToolDef


def send_webhook(url: str, findings: list[Finding], context: str) -> None:
    lines = [f"mcpscan alert ({context})"] + [
        f"- [{f.severity}] {f.rule_id} {f.server}/{f.tool}: {f.title}" for f in findings[:10]]
    body = json.dumps({"text": "\n".join(lines), "content": "\n".join(lines)}).encode()  # Slack + Discord keys
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:  # alerting must never break the proxy
        print(f"[mcpscan] webhook failed: {e}", file=sys.stderr)


def inspect_tools_list(server: str, tools_raw: list, baseline_path: str, webhook: str | None,
                       pin_if_missing: bool = True) -> list[Finding]:
    tools = [ToolDef.from_mcp(server, t) for t in tools_raw]
    findings = engine.scan_tools(tools)
    base = pinning.load(baseline_path)
    if base and server in base.get("servers", {}):
        findings.extend(pinning.diff({"servers": {server: base["servers"][server]}}, tools))
    elif pin_if_missing:
        merged = base or {"version": 1, "servers": {}}
        merged["servers"][server] = pinning.snapshot(tools)["servers"].get(server, {})
        pinning.save(baseline_path, merged)
        print(f"[mcpscan] pinned baseline for '{server}' ({len(tools)} tools)", file=sys.stderr)
    notable = [f for f in findings if SEVERITY_ORDER[f.severity] >= 1]
    for f in notable:
        print(f"[mcpscan] {f.severity.upper()} {f.rule_id} {f.server}/{f.tool}: {f.title}", file=sys.stderr)
    if webhook and any(f.severity == "critical" for f in notable):
        send_webhook(webhook, [f for f in notable if f.severity == "critical"], f"proxy:{server}")
    return findings


def _report(findings: list[Finding], webhook: str | None, server: str) -> None:
    for f in findings:
        print(f"[mcpscan] {f.severity.upper()} {f.rule_id} {f.server}/{f.tool}: {f.title} {f.evidence[:80]}", file=sys.stderr)
    crit = [f for f in findings if f.severity == "critical"]
    if webhook and crit:
        send_webhook(webhook, crit, f"proxy:{server}")


def run(server_name: str, cmd: list[str], baseline_path: str, webhook: str | None, block_critical: bool,
        egress: bool = False, allow_hosts: list[str] | None = None, block_egress: bool = False) -> int:
    import os
    from . import egress as egress_mod
    allow = list(allow_hosts or [])
    env = None
    mon = None
    if egress:
        mon = egress_mod.EgressProxy(allow, server_name, block_egress, on_finding=lambda f: _report([f], webhook, server_name))
        mon.start()
        env = {**os.environ, **mon.env()}
        print(f"[mcpscan] egress monitor on 127.0.0.1:{mon.port} (allowlist: {allow or 'none, logging only'})", file=sys.stderr)
    child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1, env=env)
    pending_list_ids: set = set()
    pending_calls: dict = {}
    lock = threading.Lock()

    def client_to_server() -> None:
        for line in sys.stdin:
            try:
                msg = json.loads(line)
                if msg.get("method") == "tools/list" and "id" in msg:
                    with lock:
                        pending_list_ids.add(msg["id"])
                if msg.get("method") == "tools/call" and isinstance(msg.get("params"), dict):
                    tname = str(msg["params"].get("name", ""))
                    if "id" in msg:
                        with lock:
                            pending_calls[msg["id"]] = tname
                    _report(egress_mod.scan_jsonrpc_payload(json.dumps(msg["params"].get("arguments", {})), server=server_name,
                                                            tool=tname, direction="arguments", allow=allow), webhook, server_name)
            except json.JSONDecodeError:
                pass
            try:
                child.stdin.write(line if line.endswith("\n") else line + "\n")
                child.stdin.flush()
            except (BrokenPipeError, OSError):
                break
        try:
            child.stdin.close()
        except OSError:
            pass

    threading.Thread(target=client_to_server, daemon=True).start()
    for line in child.stdout:
        out = line
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            msg = None
        if isinstance(msg, dict) and "id" in msg:
            with lock:
                is_list = msg["id"] in pending_list_ids
                pending_list_ids.discard(msg["id"])
                called = pending_calls.pop(msg["id"], None)
            if called is not None and "result" in msg:
                text = json.dumps(msg["result"], ensure_ascii=False)
                from . import tier1
                rf = egress_mod.scan_jsonrpc_payload(text, server=server_name, tool=called, direction="result", allow=[])
                # a tool *result* that tries to instruct the agent is the classic indirect injection vector
                rf += [f for f in tier1.scan_text(text, tool=called, server=server_name, location="result") if f.confidence >= 0.8]
                _report(rf, webhook, server_name)
            if is_list and isinstance(msg.get("result"), dict):
                findings = inspect_tools_list(server_name, msg["result"].get("tools", []), baseline_path, webhook)
                if block_critical and any(f.severity == "critical" for f in findings):
                    out = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {
                        "code": -32000, "message": "mcpscan blocked this server: critical findings in tools/list"}}) + "\n"
        sys.stdout.write(out if out.endswith("\n") else out + "\n")
        sys.stdout.flush()
    code = child.wait()
    if mon:
        mon.stop()
    return code
