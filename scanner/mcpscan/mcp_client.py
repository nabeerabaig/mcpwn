"""Minimal stdio MCP client: initialize -> notifications/initialized -> tools/list (paginated)."""
from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time

from .models import ServerSpec, ToolDef

PROTOCOL_VERSION = "2025-06-18"


class McpError(Exception):
    pass


class StdioSession:
    def __init__(self, spec: ServerSpec, timeout: float = 15.0):
        self.spec = spec
        self.timeout = timeout
        env = {**os.environ, **{k: str(v) for k, v in (spec.env or {}).items()}}
        try:
            self.proc = subprocess.Popen(
                [spec.command, *map(str, spec.args)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=env, text=True, bufsize=1,
            )
        except (OSError, ValueError) as e:
            raise McpError(f"cannot start server: {e}") from e
        self._q: queue.Queue = queue.Queue()
        self._id = 0
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        assert self.proc.stdout
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self._q.put(json.loads(line))
            except json.JSONDecodeError:
                continue  # servers sometimes log to stdout
        self._q.put(None)

    def _send(self, obj: dict) -> None:
        assert self.proc.stdin
        try:
            self.proc.stdin.write(json.dumps(obj) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise McpError("server closed the connection") from e

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        rid = self._id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        deadline = time.time() + self.timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise McpError(f"timeout waiting for {method}")
            try:
                msg = self._q.get(timeout=remaining)
            except queue.Empty:
                raise McpError(f"timeout waiting for {method}")
            if msg is None:
                raise McpError("server exited before responding")
            if msg.get("id") == rid:
                if "error" in msg:
                    raise McpError(f"{method} error: {msg['error']}")
                return msg.get("result") or {}

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


def _parse_http_body(raw: str, content_type: str, rid) -> dict | None:
    """Streamable HTTP replies are either a JSON body or an SSE stream containing the response."""
    if "text/event-stream" in content_type:
        for block in raw.split("\n\n"):
            data = "\n".join(l[5:].strip() for l in block.splitlines() if l.startswith("data:"))
            if not data:
                continue
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict) and msg.get("id") == rid:
                return msg
        return None
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(msg, list):
        msg = next((m for m in msg if isinstance(m, dict) and m.get("id") == rid), None)
    return msg


def fetch_tools_http(spec: ServerSpec, timeout: float = 15.0) -> list[ToolDef]:
    import urllib.error
    import urllib.request
    session_id = None
    counter = [0]

    def post(payload: dict, expect_response: bool = True) -> dict | None:
        headers = {"content-type": "application/json", "accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": PROTOCOL_VERSION, **{str(k): str(v) for k, v in (spec.headers or {}).items()}}
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        req = urllib.request.Request(spec.url, data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                sid = resp.headers.get("Mcp-Session-Id")
                body = resp.read().decode("utf-8", "replace")
                ctype = resp.headers.get("content-type", "")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise McpError(f"http error: {e}") from e
        nonlocal_set(sid)
        if not expect_response:
            return None
        msg = _parse_http_body(body, ctype, payload.get("id"))
        if msg is None:
            raise McpError(f"no response to {payload.get('method')}")
        if "error" in msg:
            raise McpError(f"{payload.get('method')} error: {msg['error']}")
        return msg.get("result") or {}

    def nonlocal_set(sid):
        nonlocal session_id
        if sid:
            session_id = sid

    def rpc(method, params=None):
        counter[0] += 1
        return post({"jsonrpc": "2.0", "id": counter[0], "method": method, "params": params or {}})

    rpc("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "mcpscan", "version": "0.2.0"}})
    post({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect_response=False)
    tools: list[ToolDef] = []
    cursor = None
    for _ in range(50):
        res = rpc("tools/list", {"cursor": cursor} if cursor else {})
        tools.extend(ToolDef.from_mcp(spec.name, t, spec.source) for t in res.get("tools", []))
        cursor = res.get("nextCursor")
        if not cursor:
            break
    return tools


def fetch_tools(spec: ServerSpec, timeout: float = 15.0) -> list[ToolDef]:
    if spec.transport in ("http", "streamable-http", "streamableHttp") and spec.url:
        return fetch_tools_http(spec, timeout)
    if spec.transport != "stdio":
        raise McpError(f"transport '{spec.transport}' not supported (stdio and streamable HTTP only; legacy SSE is not)")
    sess = StdioSession(spec, timeout)
    try:
        sess.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcpscan", "version": "0.2.0"},
        })
        sess._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools: list[ToolDef] = []
        cursor = None
        for _ in range(50):
            res = sess.request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(ToolDef.from_mcp(spec.name, t, spec.source) for t in res.get("tools", []))
            cursor = res.get("nextCursor")
            if not cursor:
                break
        return tools
    finally:
        sess.close()
