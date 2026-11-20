"""Phase 4: egress monitoring.

Two complementary pieces:

1. EgressProxy: a small local HTTP/HTTPS forward proxy. Run an MCP server with HTTP(S)_PROXY pointed at it
   (`proxy --egress` does this for you). It logs every destination host and flags
     - hosts not on the allowlist,
     - credential-shaped data in plain-HTTP requests (HTTPS bodies are opaque to a CONNECT tunnel).
   Limit: only traffic from programs that honor HTTP(S)_PROXY is seen. A server that opens raw sockets or
   ignores proxy variables is not observed; use a container with --network none (sandbox.py) for hard
   enforcement.

2. scan_jsonrpc_payload(): inspects tools/call arguments and results passing through the stdio proxy
   for credential patterns and URLs to non-allowlisted hosts. Works regardless of proxy settings.
"""
from __future__ import annotations

import http.server
import json
import re
import select
import socket
import socketserver
import sys
import threading
import urllib.parse
from fnmatch import fnmatch

from .models import Finding

CREDENTIAL_PATTERNS = [
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Anthropic/OpenAI-style key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("password assignment", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key)\s*[=:]\s*\S{6,}")),
]
URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)(?::\d+)?[^\s\"'<>]*")


def find_credentials(text: str) -> list[str]:
    return [name for name, rx in CREDENTIAL_PATTERNS if rx.search(text)]


def host_allowed(host: str, allow: list[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(fnmatch(host, p.lower()) or host == p.lower().lstrip("*.") for p in allow)


def scan_jsonrpc_payload(text: str, *, server: str, tool: str = "", direction: str, allow: list[str]) -> list[Finding]:
    out: list[Finding] = []
    creds = find_credentials(text)
    for c in creds:
        out.append(Finding("T4-EGRESS-CREDENTIAL", 4, f"Credential-shaped data in tool {direction}",
                           f"Found a {c} in MCP {direction} traffic.", 0.85 if direction == "arguments" else 0.6,
                           server=server, tool=tool, evidence=c))
    for m in URL_RE.finditer(text):
        host = m.group(1)
        if allow and not host_allowed(host, allow):
            out.append(Finding("T4-EGRESS-UNREGISTERED-HOST", 4, "URL to unregistered domain",
                               f"Tool {direction} reference {host}, which is not on the allowlist.",
                               0.75 if creds else 0.4, server=server, tool=tool, evidence=m.group(0)[:120]))
            break
    return out


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    monitor: "EgressProxy"

    def log_message(self, *a):  # silence default logging
        pass

    def _record(self, host: str, detail: str = "", creds: list[str] | None = None):
        self.monitor.record(host, self.command, detail, creds or [])

    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        port = int(port or 443)
        self._record(host, "CONNECT (TLS tunnel; body not inspectable)")
        if self.monitor.block_unregistered and not host_allowed(host, self.monitor.allow):
            self.send_error(403, "mcpscan: destination not allowlisted")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            self.send_error(502)
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        conns = [self.connection, upstream]
        try:
            while True:
                r, _, x = select.select(conns, [], conns, 30)
                if x or not r:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (upstream if s is self.connection else self.connection).sendall(data)
        finally:
            upstream.close()

    def _forward(self):
        parsed = urllib.parse.urlsplit(self.path)
        host = parsed.hostname or ""
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        creds = find_credentials((self.path + " " + body.decode("utf-8", "replace")))
        self._record(host, self.path[:120], creds)
        if self.monitor.block_unregistered and not host_allowed(host, self.monitor.allow):
            self.send_error(403, "mcpscan: destination not allowlisted")
            return
        import http.client
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        try:
            c = conn_cls(host, parsed.port, timeout=15)
            hdrs = {k: v for k, v in self.headers.items() if k.lower() not in ("proxy-connection", "connection")}
            c.request(self.command, (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else ""), body, hdrs)
            resp = c.getresponse()
            data = resp.read()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            self.send_error(502)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _forward


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class EgressProxy:
    def __init__(self, allow: list[str], server_name: str, block_unregistered: bool = False,
                 on_finding=None, port: int = 0):
        self.allow, self.server_name, self.block_unregistered = allow, server_name, block_unregistered
        self.on_finding = on_finding or (lambda f: None)
        self.log: list[dict] = []
        handler = type("H", (_Handler,), {"monitor": self})
        self._srv = _Server(("127.0.0.1", port), handler)
        self.port = self._srv.server_address[1]
        self._lock = threading.Lock()

    def record(self, host: str, method: str, detail: str, creds: list[str]) -> None:
        with self._lock:
            self.log.append({"host": host, "method": method, "detail": detail, "credentials": creds})
        unreg = bool(self.allow) and not host_allowed(host, self.allow)
        if unreg or creds:
            conf = 0.9 if (unreg and creds) else (0.85 if creds else 0.6)
            rule = "T4-EGRESS-CREDENTIAL" if creds else "T4-EGRESS-UNREGISTERED-HOST"
            self.on_finding(Finding(rule, 4, "Outbound request from MCP server" + (" carrying credentials" if creds else " to unregistered host"),
                                    f"{method} {host} {detail}".strip() + (f" [{', '.join(creds)}]" if creds else ""),
                                    conf, server=self.server_name, evidence=host))

    def start(self) -> None:
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()

    def env(self) -> dict:
        url = f"http://127.0.0.1:{self.port}"
        return {"HTTP_PROXY": url, "HTTPS_PROXY": url, "http_proxy": url, "https_proxy": url}
