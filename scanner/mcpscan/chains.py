"""Phase 3: capability graph + cross-server exploit chain detection."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import ToolDef

CAP_PATTERNS = {
    "credential": r"secret|credential|password|token|api[_ -]?key|keychain|vault|ssh|private[_ -]?key|env(ironment)? var",
    "execute": r"\b(exec|execute|run|shell|bash|powershell|command|eval|spawn|terminal|subprocess)\b",
    "network": r"\b(http|https|url|fetch|request|webhook|post|upload|send|email|smtp|slack|discord|curl|download|browse|navigate)\b",
    "write": r"\b(write|create|edit|modify|update|delete|remove|save|append|overwrite|put|patch|set|config)\b",
    "read": r"\b(read|list|get|open|cat|search|find|query|view|fetch|load|show|retrieve)\b",
    "financial": r"\b(pay|payment|transfer|invoice|charge|purchase|buy|wallet|bank|refund|transaction|trade)\b",
}
CAP_SEVERITY = {"read": 1, "write": 3, "network": 3, "execute": 5, "credential": 4, "financial": 5}

# (source cap, sink cap, label, risk multiplier)
CHAIN_RULES = [
    ("credential", "network", "Credential theft", 1.0),
    ("read", "network", "Data exfiltration", 0.8),
    ("write", "execute", "Config-write to code execution (RCE)", 0.95),
    ("network", "execute", "Remote content to code execution", 0.9),
    ("read", "financial", "Data-driven financial action", 0.7),
]


@dataclass
class ToolCaps:
    server: str
    tool: str
    caps: set


@dataclass
class Chain:
    label: str
    source: ToolCaps
    sink: ToolCaps
    source_cap: str
    sink_cap: str
    score: float
    cross_server: bool

    def to_dict(self):
        return {"label": self.label, "score": self.score, "cross_server": self.cross_server,
                "source": f"{self.source.server}/{self.source.tool} ({self.source_cap})",
                "sink": f"{self.sink.server}/{self.sink.tool} ({self.sink_cap})"}


def classify(tool: ToolDef) -> ToolCaps:
    name_text = re.sub(r"[_\-.]", " ", tool.name).lower()
    desc = tool.description.lower()[:400]
    caps = set()
    for cap, pat in CAP_PATTERNS.items():
        if re.search(pat, name_text):
            caps.add(cap)
    # description matches count only for high-impact caps, to limit noise
    for cap in ("credential", "execute", "financial"):
        if re.search(CAP_PATTERNS[cap], desc):
            caps.add(cap)
    if re.search(CAP_PATTERNS["network"], desc) and re.search(r"https?://|\b(send|post|upload)\b", desc):
        caps.add("network")
    # read-only intent heuristics
    if not caps:
        caps.add("read")
    return ToolCaps(tool.server, tool.name, caps)


def find_chains(tools: list[ToolDef], include_same_server: bool = True) -> list[Chain]:
    classified = [classify(t) for t in tools]
    chains: list[Chain] = []
    for src_cap, sink_cap, label, mult in CHAIN_RULES:
        sources = [c for c in classified if src_cap in c.caps]
        sinks = [c for c in classified if sink_cap in c.caps]
        for s in sources:
            for k in sinks:
                if s is k:
                    continue
                cross = s.server != k.server
                if not cross and not include_same_server:
                    continue
                reach = 1.0 if cross else 0.6  # a cross-server chain is invisible to per-server review
                sev = CAP_SEVERITY[src_cap] * CAP_SEVERITY[sink_cap]
                score = round(min(10.0, sev * mult * reach / 2.5), 1)
                chains.append(Chain(label, s, k, src_cap, sink_cap, score, cross))
    chains.sort(key=lambda c: (-c.score, c.label))
    # dedupe identical (source tool, sink tool) keeping highest
    seen, out = set(), []
    for c in chains:
        key = (c.source.server, c.source.tool, c.sink.server, c.sink.tool)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def render_text(chains: list[Chain], limit: int = 15) -> str:
    if not chains:
        return "No dangerous capability chains found."
    lines = [f"Top {min(limit, len(chains))} of {len(chains)} potential kill chains (score 0-10):\n"]
    for c in chains[:limit]:
        tag = "CROSS-SERVER" if c.cross_server else "same-server"
        lines.append(f"[{c.score:4.1f}] {c.label}  ({tag})")
        lines.append(f"   {c.source.server}/{c.source.tool} [{c.source_cap}]")
        lines.append(f"      |--> {c.sink.server}/{c.sink.tool} [{c.sink_cap}]\n")
    return "\n".join(lines)


def render_html(chains: list[Chain]) -> str:
    import html
    rows = "".join(
        f"<tr><td>{c.score}</td><td>{html.escape(c.label)}</td>"
        f"<td>{html.escape(c.source.server)}/{html.escape(c.source.tool)}<br><small>{c.source_cap}</small></td>"
        f"<td>&rarr;</td>"
        f"<td>{html.escape(c.sink.server)}/{html.escape(c.sink.tool)}<br><small>{c.sink_cap}</small></td>"
        f"<td>{'cross-server' if c.cross_server else 'same-server'}</td></tr>"
        for c in chains[:50])
    return ("<!doctype html><meta charset=utf-8><title>MCP kill chains</title>"
            "<style>body{font:14px system-ui;margin:2rem}table{border-collapse:collapse}"
            "td,th{border:1px solid #ccc;padding:6px 10px}</style><h1>MCP kill chains</h1>"
            "<table><tr><th>Score</th><th>Chain</th><th>Source</th><th></th><th>Sink</th><th>Scope</th></tr>"
            f"{rows}</table>")
