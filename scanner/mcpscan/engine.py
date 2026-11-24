"""Detection pipeline: walks supported MCP metadata and runs Tier 1 -> 2 -> (optional) 3."""
from __future__ import annotations

from typing import Iterator, Any

from . import tier1, tier2, tier3
from .models import Finding, ToolDef
from .normalize import normalize_text

MAX_CONTENT_DEPTH = 32
MAX_CONTENT_NODES = 20000
MAX_TEXT_CHARS = 1_000_000
MAX_PARAMETER_NODES = 20_000
MAX_PARAMETER_NAME_CHARS = 1_000_000


def _walk_text(node: Any, path: str, *, depth: int = 0, budget: list | None = None):
    """Yield bounded (location, text) pairs without coercing arbitrary objects to strings."""
    if budget is None:
        budget = [MAX_CONTENT_NODES, MAX_TEXT_CHARS, None]
    if budget[2] is not None:
        return
    if budget[0] <= 0:
        budget[2] = "node count limit exceeded"
        yield (path, None, budget[2])
        return
    budget[0] -= 1
    if depth > MAX_CONTENT_DEPTH:
        yield (path, None, "maximum content depth limit exceeded")
        return
    if isinstance(node, str):
        if len(node) > budget[1]:
            budget[2] = "aggregate text size limit exceeded"
            yield (path, None, budget[2])
            return
        budget[1] -= len(node)
        yield (path, node, None)
    elif isinstance(node, dict):
        for key, value in node.items():
            if budget[2] is not None:
                return
            if not isinstance(key, str):
                yield (path, None, "non-string object key")
                continue
            yield from _walk_text(key, f"{path}.{key}#key", depth=depth + 1, budget=budget)
            if budget[2] is not None:
                return
            if key in ("properties", "$defs", "definitions") and isinstance(value, dict):
                for property_name, property_value in value.items():
                    if budget[2] is not None:
                        return
                    yield from _walk_text(property_name, f"{path}.{key}.{property_name}#name",
                                           depth=depth + 2, budget=budget)
                    yield from _walk_text(property_value, f"{path}.{key}.{property_name}",
                                           depth=depth + 2, budget=budget)
            else:
                yield from _walk_text(value, f"{path}.{key}", depth=depth + 1, budget=budget)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            if budget[2] is not None:
                return
            yield from _walk_text(value, f"{path}[{index}]", depth=depth + 1, budget=budget)
    elif node is None:
        yield (path, None, "not applicable: null value")
    elif isinstance(node, (bool, int, float)):
        yield (path, None, "not applicable: non-text scalar")
    else:
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
    # One shared budget covers the entire tool definition, not each root field separately.
    budget = [MAX_CONTENT_NODES, MAX_TEXT_CHARS, None]
    for root, value in fields:
        if budget[2] is not None:
            yield (root, None, budget[2])
            return
        yield from _walk_text(value, root, budget=budget)


def scan_tool_with_coverage(tool: ToolDef, sibling_names: set[str] | None = None,
                            use_llm: bool = False) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    sibling_names = sibling_names or set()
    ctx = dict(tool=tool.name, server=tool.server, source=tool.source)
    scanned, skipped, discovered = [], [], []
    parameter_scan_limits = []
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

    # Parameter-name checks share one independent budget across input and output schemas.
    parameter_budget = [MAX_PARAMETER_NODES, MAX_PARAMETER_NAME_CHARS]
    parameter_findings, parameter_limit = tier2.scan_param_names_with_status(
        tool.input_schema, tool=tool.name, server=tool.server, source=tool.source,
        budget=parameter_budget
    )
    findings.extend(parameter_findings)
    if parameter_limit:
        parameter_scan_limits.append({"location": "inputSchema.properties", "reason": parameter_limit})
    if isinstance(tool.output_schema, dict):
        parameter_findings, parameter_limit = tier2.scan_param_names_with_status(
            tool.output_schema, tool=tool.name, server=tool.server,
            source=tool.source, root_path="outputSchema", budget=parameter_budget
        )
        findings.extend(parameter_findings)
        if parameter_limit:
            parameter_scan_limits.append({"location": "outputSchema.properties", "reason": parameter_limit})
    skipped.extend(parameter_scan_limits)

    # A directive hidden in schema metadata (not the description) is more suspicious than in prose.
    for finding in findings:
        if (finding.tier == 2 and finding.location != "description"
                and finding.confidence >= 0.5 and finding.rule_id != "T2-INSTRUCTION-PARAM"):
            finding.rescore(finding.confidence + 0.05)

    findings = dedupe(findings)
    semantic_review_status = "not_requested"
    semantic_review_disagreed = False
    if use_llm:
        if tier3.backend_available():
            static_tier_two = any(finding.tier == 2 for finding in findings)
            extra, semantic_review_status = tier3.apply_with_status(tool, findings)
            semantic_review_disagreed = semantic_review_status == "benign" and static_tier_two
            findings.extend(extra)
        else:
            semantic_review_status = "unavailable"
    semantic_applied = semantic_review_status in ("flagged", "benign")
    if use_llm:
        for finding in findings:
            finding.semantic_status = semantic_review_status

    for finding in findings:
        finding.related_finding_ids = sorted({
            other.finding_id for other in findings
            if other.finding_id != finding.finding_id
            and other.server == finding.server and other.tool == finding.tool
            and other.category == finding.category
        })

    total = len(discovered)
    scanned_count = len(scanned)
    unsupported_count = sum("unsupported" in item["reason"] or "limit" in item["reason"] or "non-string" in item["reason"]
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
        "unsupported_fields": [item for item in skipped if "unsupported" in item["reason"] or "limit" in item["reason"] or "non-string" in item["reason"]],
        "scan_errors": errors,
        "semantic_analysis_applied": semantic_applied,
        "semantic_review_status": semantic_review_status,
        "semantic_review_disagreed_with_static": semantic_review_disagreed,
        "dynamic_validation_performed": False,
        "dynamic_validation_status": "not_requested",
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




def aggregate_risk(findings: list[Finding]) -> list[dict]:
    """Explainable per-target roll-up; uses maximum severity rather than additive scores."""
    grouped: dict[tuple[str, str, str], list[Finding]] = {}
    for finding in findings:
        key = (finding.server, finding.tool, finding.source)
        grouped.setdefault(key, []).append(finding)
    rows = []
    for (server, tool, source), items in sorted(grouped.items()):
        unique_ids = sorted({item.finding_id for item in items})
        rows.append({
            "server": server,
            "tool": tool,
            "source": source,
            "highest_severity": max(items, key=lambda item: {"info": 0, "warning": 1, "critical": 2}[item.severity]).severity,
            "highest_confidence": max(item.confidence for item in items),
            "finding_count": len(unique_ids),
            "categories": sorted({item.category for item in items}),
            "finding_ids": unique_ids,
            "aggregation_method": "maximum_severity_and_confidence; no additive risk score",
        })
    return rows


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
