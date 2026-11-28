"""Detection pipeline: walks supported MCP metadata and runs Tier 1 -> 2 -> (optional) 3."""
from __future__ import annotations

from typing import Iterator, Any

from . import tier1, tier2, tier3
from .models import Finding, ToolDef
from .normalize import NORMALIZED_SUFFIX, OriginalEvidence, normalize_text

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
        raw_findings = (tier1.scan_text(text, location=loc, **ctx)
                        + tier2.scan_text(text, location=loc, sibling_tools=sibling_names, **ctx))
        findings.extend(raw_findings)
        normalized = normalize_text(text)
        analysis_text = normalized.analysis_text
        if analysis_text is not None and analysis_text != text:
            normalized_fields.append(loc)
            normalized_findings = (
                tier1.scan_text(analysis_text, location=loc + NORMALIZED_SUFFIX, **ctx)
                + tier2.scan_text(analysis_text, location=loc + NORMALIZED_SUFFIX,
                                  sibling_tools=sibling_names, **ctx)
            )
            original_evidence = OriginalEvidence(normalized) if normalized_findings else None
            for finding in normalized_findings:
                finding.evidence = original_evidence.restore(finding.evidence)
                finding.message += (
                    " Detected in a Unicode-normalized analysis view."
                    + (" Evidence is from the original source." if finding.evidence else
                       " No unambiguous original evidence excerpt was available.")
                )
            findings.extend(normalized_findings)
            raw_signals = {(f.rule_id, f.evidence) for f in raw_findings}
            raw_rules = {f.rule_id for f in raw_findings}
            new_signals = [f for f in normalized_findings if f.rule_id not in raw_rules
                           or (f.evidence and (f.rule_id, f.evidence) not in raw_signals)]
            intrinsic_matches = [f for f in raw_findings if f.tier == 1
                                 and "Text was matched after" in f.message]
            if normalized.obfuscation_transformed and (new_signals or intrinsic_matches):
                findings.append(Finding(
                    rule_id="T1-UNICODE-OBFUSCATION", tier=1,
                    title="Unicode obfuscation in suspicious instruction",
                    message=("A suspicious instruction was detectable only after removing invisible formatting "
                             "characters or normalizing lookalike Unicode characters."),
                    confidence=0.9, server=tool.server, tool=tool.name,
                    location=loc, source=tool.source,
                    evidence=next((item.evidence for item in (new_signals or intrinsic_matches) if item.evidence), ""),
                ))
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
        key = (f.rule_id, f.source, f.server, f.tool,
               f.location.removesuffix(NORMALIZED_SUFFIX) if f.evidence else f.location, f.evidence)
        current = seen.get(key)
        if (current is None or f.confidence > current.confidence
                or (f.confidence == current.confidence and current.location.endswith(NORMALIZED_SUFFIX)
                    and not f.location.endswith(NORMALIZED_SUFFIX))):
            seen[key] = f
    return list(seen.values())




def _descriptor_issues(surface_name: str, item: dict) -> list[dict]:
    """Validate protocol descriptor fields without coercing malformed values to text."""
    issues = []

    def require_string(key: str):
        value = item.get(key)
        if not isinstance(value, str) or not value.strip():
            issues.append({"location": key, "reason": f"{key} must be a nonempty string"})

    def optional_string(key: str):
        if key in item and item[key] is not None and not isinstance(item[key], str):
            issues.append({"location": key, "reason": f"{key} must be a string when provided"})

    if surface_name == "prompts":
        require_string("name")
    elif surface_name == "resources":
        require_string("name")
        require_string("uri")
    elif surface_name == "resource_templates":
        require_string("name")
        require_string("uriTemplate")

    for key in ("title", "description", "mimeType"):
        optional_string(key)
    for key in ("annotations", "_meta"):
        if key in item and item[key] is not None and not isinstance(item[key], dict):
            issues.append({"location": key, "reason": f"{key} must be an object when provided"})

    if surface_name == "prompts":
        arguments = item.get("arguments", [])
        if not isinstance(arguments, list):
            issues.append({"location": "arguments", "reason": "prompt arguments must be an array"})
        else:
            seen_argument_names = set()
            for index, argument in enumerate(arguments):
                prefix = f"arguments[{index}]"
                if not isinstance(argument, dict):
                    issues.append({"location": prefix, "reason": "prompt argument must be an object"})
                    continue
                if not isinstance(argument.get("name"), str) or not argument["name"].strip():
                    issues.append({"location": f"{prefix}.name", "reason": "prompt argument name must be a nonempty string"})
                else:
                    if argument["name"] in seen_argument_names:
                        issues.append({"location": f"{prefix}.name", "reason": "duplicate prompt argument name"})
                    seen_argument_names.add(argument["name"])
                if ("description" in argument and argument["description"] is not None
                        and not isinstance(argument["description"], str)):
                    issues.append({"location": f"{prefix}.description",
                                   "reason": "prompt argument description must be a string"})
                if ("required" in argument and type(argument["required"]) is not bool):
                    issues.append({"location": f"{prefix}.required",
                                   "reason": "prompt argument required flag must be boolean"})
    return issues


def scan_protocol_surfaces(surfaces: list[dict], use_llm: bool = False
                          ) -> tuple[list[Finding], list[dict]]:
    """Scan prompt/resource descriptors returned by MCP list methods; never fetch bodies."""
    findings: list[Finding] = []
    coverage: list[dict] = []
    surface_types = {
        "prompts": ("mcp_prompt", "prompt_definition"),
        "resources": ("mcp_resource", "resource_descriptor"),
        "resource_templates": ("mcp_resource_template", "resource_template"),
    }
    for surface in surfaces:
        if not isinstance(surface, dict):
            coverage.append({
                "source_type": "mcp_protocol_metadata", "source_id": "unknown",
                "content_type": "protocol_metadata", "status": "unsupported",
                "fields_discovered": 0, "fields_scanned": 0,
                "fields_skipped": [{"location": "descriptor", "reason": "surface inventory entry is not an object"}],
                "unsupported_fields": [{"location": "descriptor", "reason": "surface inventory entry is not an object"}],
                "scan_errors": [], "semantic_analysis_applied": False,
                "semantic_review_status": "not_requested",
                "dynamic_validation_performed": False,
                "dynamic_validation_status": "not_requested",
            })
            continue
        surface_name = surface.get("surface", "")
        source_type, content_type = surface_types.get(
            surface_name, ("mcp_protocol_metadata", "protocol_metadata")
        )
        server = surface.get("server", "")
        source = surface.get("source", "")
        status = surface.get("status", "failed")
        items = surface.get("items", [])
        if status != "scanned":
            mapped_status = {
                "not_advertised": "not_applicable",
                "unsupported": "unsupported",
                "failed": "failed",
                "not_in_snapshot": "unsupported",
            }.get(status, "failed")
            coverage.append({
                "source_type": source_type,
                "source_id": server,
                "content_type": content_type,
                "status": mapped_status,
                "fields_discovered": 0,
                "fields_scanned": 0,
                "fields_skipped": [{"location": surface_name, "reason": surface.get("reason", status)}],
                "unsupported_fields": ([{"location": surface_name, "reason": surface.get("reason", status)}]
                                       if mapped_status == "unsupported" else []),
                "scan_errors": [surface.get("reason", status)] if mapped_status == "failed" else [],
                "semantic_analysis_applied": False,
                "semantic_review_status": "not_requested",
                "dynamic_validation_performed": False,
                "dynamic_validation_status": "not_requested",
            })
            continue
        if not isinstance(items, list) or not items:
            coverage.append({
                "source_type": source_type, "source_id": server,
                "content_type": content_type, "status": "fully_scanned",
                "fields_discovered": 0, "fields_scanned": 0,
                "fields_skipped": [], "unsupported_fields": [], "scan_errors": [],
                "semantic_analysis_applied": False,
                "semantic_review_status": "not_requested",
                "dynamic_validation_performed": False,
                "dynamic_validation_status": "not_requested",
            })
            continue
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                coverage.append({
                    "source_type": source_type, "source_id": f"{server}/{surface_name}/{index + 1}",
                    "content_type": content_type, "status": "unsupported",
                    "fields_discovered": 0, "fields_scanned": 0,
                    "fields_skipped": [{"location": surface_name, "reason": "descriptor is not an object"}],
                    "unsupported_fields": [{"location": surface_name, "reason": "descriptor is not an object"}],
                    "scan_errors": [], "semantic_analysis_applied": False,
                    "semantic_review_status": "not_requested",
                    "dynamic_validation_performed": False,
                    "dynamic_validation_status": "not_requested",
                })
                continue
            descriptor_issues = _descriptor_issues(surface_name, item)
            description = item.get("description", "")
            if not isinstance(description, str):
                description = ""
            if surface_name == "prompts":
                label = item.get("name") if isinstance(item.get("name"), str) else f"prompt-{index + 1}"
                arguments = item.get("arguments", [])
                properties = {}
                if isinstance(arguments, list):
                    for argument in arguments:
                        if not isinstance(argument, dict):
                            continue
                        argument_name = argument.get("name")
                        if not isinstance(argument_name, str) or not argument_name.strip():
                            continue
                        argument_description = argument.get("description", "")
                        properties[argument_name] = {
                            "type": "string",
                            "description": argument_description if isinstance(argument_description, str) else "",
                        }
                schema = {"type": "object", "properties": properties}
                tool = ToolDef(server, f"prompt:{label}", description,
                               schema, source, extra={"promptMetadata": item})
            elif surface_name == "resources":
                label = item.get("name") if isinstance(item.get("name"), str) else f"resource-{index + 1}"
                tool = ToolDef(server, f"resource:{label}", description, {}, source,
                               extra={"resourceMetadata": item})
            else:
                label = item.get("name") if isinstance(item.get("name"), str) else f"resource-template-{index + 1}"
                tool = ToolDef(server, f"resource-template:{label}", description, {}, source,
                               extra={"resourceTemplateMetadata": item})
            found, record = scan_tool_with_coverage(tool, use_llm=use_llm)
            record.update(source_type=source_type, source_id=f"{server}/{surface_name}/{label}",
                          content_type=content_type)
            if descriptor_issues:
                record["fields_discovered"] += len(descriptor_issues)
                record["fields_skipped"].extend(descriptor_issues)
                record["unsupported_fields"].extend(descriptor_issues)
                record["status"] = "partially_scanned" if record["fields_scanned"] else "unsupported"
            findings.extend(found)
            coverage.append(record)
    return sorted(findings, key=lambda item: -item.confidence), coverage


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
