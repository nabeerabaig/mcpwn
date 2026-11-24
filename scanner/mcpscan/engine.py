"""Detection pipeline: walks supported MCP metadata and runs Tier 1 -> 2 -> (optional) 3."""
from __future__ import annotations

from typing import Iterator, Any

from . import tier1, tier2, tier3
from .models import Finding, ToolDef\nfrom .normalize import normalize_text

MAX_CONTENT_DEPTH = 32
MAX_CONTENT_NODES = 20000
MAX_TEXT_CHARS = 1_000_000


def _walk_text(node: Any, path: str, *, depth: int = 0, budget: list[int] | None = None):
    """Yield bounded (location, text) pairs without coercing arbitrary objects to strings."""
    if budget is None:
        budget = [MAX_CONTENT_NODES, MAX_TEXT_CHARS]
    if budget[0] <= 0:
        yield (path, None, "node limit exceeded")
        return
    budget[0] -= 1
    if depth > MAX_CONTENT_DEPTH:
        yield (path, None, "maximum content depth limit exceeded")
        return
    if isinstance(node, str):
        if len(node) > budget[1]:
            yield (path, None, "text size limit exceeded")
            budget[1] = 0
            return
        budget[1] -= len(node)
        yield (path, node, None)
    elif isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                yield (path, None, "non-string object key")
                continue
            if key in ("properties", "$defs", "definitions") and isinstance(value, dict):
                for property_name, property_value in value.items():
                    if isinstance(property_name, str):
                        yield (f"{path}.{key}.{property_name}#name", property_name, None)
                    else:
                        yield (f"{path}.{key}", None, "non-string schema property name")
                    yield from _walk_text(property_value, f"{path}.{key}.{property_name}",
                                           depth=depth + 2, budget=budget)
            else:
                yield from _walk_text(value, f"{path}.{key}", depth=depth + 1, budget=budget)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk_text(value, f"{path}[{index}]", depth=depth + 1, budget=budget)
    elif node is not None and isinstance(node, (bool, int, float)):
        yield (path, None, "not applicable: non-text scalar")
    elif node is not None:
        yield (path, None, f"unsupported value type: {type(node).__name__}")


def iter_schema_strings(node, path: str = "inputSchema") -> Iterator[tuple[str, str]]:
    """Backward-compatible iterator over strings in JSON Schema structures."""
    for location, text, _reason in _walk_text(node, path):
        if isinstance(text, str):
            yield location, text


def _tool_content(tool: ToolDef):
    fields = [
        ("name", tool.name),
        ("description", tool.description),
        ("inputSchema", tool.input_schema),
    ]
    if tool.output_schema is not None:
        fields.append(("outputSchema", tool.output_schema))
    if tool.annotations:
        fields.append(("annotations", tool.annotations))
    if tool.meta:
        fields.append(("_meta", tool.meta))
    if tool.extra:
        fields.append(("additionalMetadata", tool.extra))
    for root, value in fields:
        yield from _walk_text(value, root)


def scan_tool_with_coverage(tool: ToolDef, sibling_names: set[str] | None = None,
                            use_llm: bool = False) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    sibling_names = sibling_names or set()
    ctx = dict(tool=tool.name, server=tool.server, source=tool.source)
    scanned, skipped, discovered = [], [], []
    texts = []
    errors = []
    try:
        for location, value, reason in _tool_content(tool):
            discovered.append(location)
            if isinstance(value, str):
                if value:
                    scanned.append(location)
                    texts.append((location, value))
                else:
                    skipped.append({"location": location, "reason": "empty text"})
            elif reason:
                skipped.append({"location": location, "reason": reason})
    except (RecursionError, RuntimeError, TypeError, ValueError) as exc:
        errors.append(type(exc).__name__)

    normalized_fields = []
    suspicious_unicode = []
    for loc, text in texts:
        findings.extend(tier1.scan_text(text, location=loc, **ctx))
        findings.extend(tier2.scan_text(text, location=loc, sibling_tools=sibling_names, **ctx))
        normalized = normalize_text(text)
        if normalized.transformed and normalized.normalized is not None:
            normalized_fields.append(loc)
            normalized_findings = tier2.scan_text(
                normalized.normalized, location=loc + "#nfkc",
                sibling_tools=sibling_names, **ctx
            )
            for finding in normalized_findings:
                finding.evidence = text[:200]
                finding.message += " Detected in an NFKC-normalized representation; evidence is preserved from the original source."
            findings.extend(normalized_findings)
        if len(suspicious_unicode) < 200:
            for character in normalized.suspicious_characters:
                if len(suspicious_unicode) >= 200:
                    break
                suspicious_unicode.append({"location": loc, **character})

    findings.extend(tier2.scan_param_names(tool.input_schema, tool=tool.name, server=tool.server, source=tool.source))
    if isinstance(tool.output_schema, dict):
        findings.extend(tier2.scan_param_names(tool.output_schema, tool=tool.name, server=tool.server,
                                                source=tool.source, root_path="outputSchema"))

    # A directive hidden in schema metadata (not the description) is more suspicious than in prose.
    for finding in findings:
        if (finding.tier == 2 and finding.location != "description"
                and finding.confidence >= 0.5 and finding.rule_id != "T2-INSTRUCTION-PARAM"):
            finding.rescore(finding.confidence + 0.05)

    findings = dedupe(findings)
    semantic_applied = False
    if use_llm and tier3.backend_available():
        extra, semantic_applied = tier3.apply_with_status(tool, findings)
        findings.extend(extra)

    total = len(discovered)
    scanned_count = len(scanned)
    unsupported_count = sum("unsupported" in item["reason"] or "limit" in item["reason"]
                             for item in skipped)
    if errors:
        status = "failed"
    elif unsupported_count:
        status = "partially_scanned" if scanned_count else "unsupported"
    elif scanned_count:
        status = "fully_scanned"
    else:
        status = "not_applicable"
    coverage = {
        "source_type": "mcp_tool",
        "source_id": f"{tool.server}/{tool.name}",
        "content_type": "tool_definition",
        "status": status,
        "fields_discovered": total,
        "fields_scanned": scanned_count,
        "fields_skipped": skipped,
        "unsupported_fields": [item for item in skipped if "unsupported" in item["reason"] or "limit" in item["reason"]],
        "scan_errors": errors,
        "semantic_analysis_applied": semantic_applied,
        "dynamic_validation_performed": False,
        "discovered_locations": discovered,
        "scanned_locations": scanned,
        "normalized_fields": normalized_fields,
        "suspicious_unicode": suspicious_unicode,
    }
    return findings, coverage


def scan_tool(tool: ToolDef, sibling_names: set[str] | None = None, use_llm: bool = False) -> list[Finding]:
    """Compatibility wrapper returning findings only."""
    return scan_tool_with_coverage(tool, sibling_names, use_llm)[0]


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.rule_id, f.server, f.tool, f.location.split("#")[0], f.evidence[:60])
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    return list(seen.values())


def scan_tools_with_coverage(tools: list[ToolDef], use_llm: bool = False) -> tuple[list[Finding], list[dict]]:
    by_server: dict[str, set[str]] = {}
    for tool in tools:
        by_server.setdefault(tool.server, set()).add(tool.name)
    findings: list[Finding] = []
    coverage: list[dict] = []
    for tool in tools:
        found, record = scan_tool_with_coverage(tool, by_server.get(tool.server, set()), use_llm)
        findings.extend(found)
        coverage.append(record)
    return sorted(findings, key=lambda finding: -finding.confidence), coverage


def scan_tools(tools: list[ToolDef], use_llm: bool = False) -> list[Finding]:
    """Compatibility wrapper returning findings only."""
    return scan_tools_with_coverage(tools, use_llm)[0]
