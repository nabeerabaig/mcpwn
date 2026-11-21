"""JSON, SARIF 2.1.0 and terminal output."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import replace

from . import __version__
from .models import Finding, SEVERITY_ORDER

SARIF_LEVEL = {"critical": "error", "warning": "warning", "info": "note"}


def without_evidence(findings: list[Finding]) -> list[Finding]:
    """Discard raw snippets and free-form text, keeping CI locations and severity."""
    return [replace(f, evidence="", title=f.rule_id,
                    message="Finding details omitted by report redaction.") for f in findings]


def filter_min(findings: list[Finding], min_conf: float) -> list[Finding]:
    return [f for f in findings if f.confidence >= min_conf]


def to_json(findings: list[Finding], extra: dict | None = None) -> str:
    counts = Counter(f.severity for f in findings)
    doc = {"tool": "mcpscan", "version": __version__,
           "summary": {"total": len(findings), **{s: counts.get(s, 0) for s in SEVERITY_ORDER}},
           "findings": [f.to_dict() for f in findings]}
    if extra:
        doc.update(extra)
    return json.dumps(doc, indent=2, ensure_ascii=False)


def to_sarif(findings: list[Finding]) -> str:
    rules, seen = [], set()
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            rules.append({"id": f.rule_id, "name": f.rule_id,
                          "shortDescription": {"text": f.title},
                          "properties": {"tier": f.tier}})
    results = []
    for f in findings:
        uri = f.source or "mcp-config"
        loc_name = ".".join(x for x in (f.server, f.tool, f.location) if x)
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.message}" + (f" [evidence: {f.evidence[:120]}]" if f.evidence else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri.replace("\\", "/")},
                                                "region": {"startLine": 1}},
                           "logicalLocations": [{"name": loc_name or "unknown"}]}],
            "properties": {"confidence": f.confidence, "tier": f.tier, "severity": f.severity},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "mcpscan", "version": __version__, "rules": rules}}, "results": results}],
    }, indent=2)


def to_text(findings: list[Finding], notes: list[str] | None = None) -> str:
    lines = []
    for n in notes or []:
        lines.append(f"note: {n}")
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)
    counts = Counter(f.severity for f in findings)
    lines.append(f"{len(findings)} finding(s): {counts.get('critical',0)} critical, "
                 f"{counts.get('warning',0)} warning, {counts.get('info',0)} info\n")
    icon = {"critical": "CRIT", "warning": "WARN", "info": "INFO"}
    for f in sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], -x.confidence)):
        where = " / ".join(x for x in (f.server, f.tool, f.location) if x) or f.source
        lines.append(f"[{icon[f.severity]}] {f.confidence:.2f}  {f.rule_id}  (tier {f.tier})")
        lines.append(f"       {f.title} - {where}")
        lines.append(f"       {f.message}")
        if f.evidence:
            lines.append(f"       evidence: {f.evidence[:140]!r}")
        lines.append("")
    return "\n".join(lines)


def to_markdown(findings: list[Finding], score: int | None = None, title: str = "mcpscan results") -> str:
    """Compact markdown suitable for a PR review comment."""
    lines = [f"### {title}"]
    if score is not None:
        lines.append(f"**Agent security score: {score}/100**")
    if not findings:
        lines.append("\nNo findings.")
        return "\n".join(lines)
    lines.append("\n| Severity | Conf. | Rule | Where | What |\n|---|---|---|---|---|")
    for f in sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], -x.confidence))[:40]:
        where = (f.source or f.server) + (f" `{f.tool}`" if f.tool and f.tool != f.source else "")
        what = f.title.replace("|", "\\|")
        lines.append(f"| {f.severity} | {f.confidence:.2f} | `{f.rule_id}` | {where} | {what} |")
    if len(findings) > 40:
        lines.append(f"\n_{len(findings) - 40} more not shown._")
    return "\n".join(lines)


def exceeds(findings: list[Finding], fail_on: str | None) -> bool:
    if not fail_on or fail_on == "none":
        return False
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[f.severity] >= threshold for f in findings)
