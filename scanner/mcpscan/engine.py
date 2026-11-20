"""Detection pipeline: walks a tool definition and runs Tier 1 -> 2 -> (optional) 3."""
from __future__ import annotations

from typing import Iterator

from . import tier1, tier2, tier3
from .models import Finding, ToolDef


def iter_schema_strings(node, path: str = "inputSchema") -> Iterator[tuple[str, str]]:
    """Yield (location, string) for every string in a JSON schema, incl. enums, defaults, titles, keys."""
    if isinstance(node, dict):
        for k, v in node.items():
            sub = f"{path}.{k}"
            if k in ("properties", "$defs", "definitions") and isinstance(v, dict):
                for pname, pval in v.items():
                    yield (f"{sub}.{pname}#name", str(pname))
                    yield from iter_schema_strings(pval, f"{sub}.{pname}")
            else:
                yield from iter_schema_strings(v, sub)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from iter_schema_strings(v, f"{path}[{i}]")
    elif isinstance(node, str):
        yield (path, node)


def scan_tool(tool: ToolDef, sibling_names: set[str] | None = None, use_llm: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    sibling_names = sibling_names or set()
    ctx = dict(tool=tool.name, server=tool.server, source=tool.source)

    texts = [("description", tool.description), ("name", tool.name)]
    texts.extend(iter_schema_strings(tool.input_schema))

    for loc, text in texts:
        if not isinstance(text, str) or not text:
            continue
        findings.extend(tier1.scan_text(text, location=loc, **ctx))
        findings.extend(tier2.scan_text(text, location=loc, sibling_tools=sibling_names, **ctx))

    findings.extend(tier2.scan_param_names(tool.input_schema, tool=tool.name, server=tool.server, source=tool.source))

    # A directive hidden in schema metadata (not the description) is more suspicious than in prose.
    for f in findings:
        if f.tier == 2 and f.location != "description" and f.confidence >= 0.5 and f.rule_id != "T2-INSTRUCTION-PARAM":
            f.rescore(f.confidence + 0.05)

    findings = dedupe(findings)
    if use_llm:
        findings.extend(tier3.apply(tool, findings))
    return findings


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.rule_id, f.server, f.tool, f.location.split("#")[0], f.evidence[:60])
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    return list(seen.values())


def scan_tools(tools: list[ToolDef], use_llm: bool = False) -> list[Finding]:
    by_server: dict[str, set[str]] = {}
    for t in tools:
        by_server.setdefault(t.server, set()).add(t.name)
    out: list[Finding] = []
    for t in tools:
        out.extend(scan_tool(t, by_server.get(t.server, set()), use_llm=use_llm))
    return sorted(out, key=lambda f: -f.confidence)
