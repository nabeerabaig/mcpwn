"""Offline, policy-based auditing of MCP snapshots across projects."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from . import engine, snapshot
from .models import Finding, SEVERITY_ORDER, ToolDef

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_PROJECTS = 100
MAX_TOOLS = 5000
PROJECT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


class AuditError(ValueError):
    """A safe diagnostic that does not include raw snapshot contents."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_):
    raise AuditError("non-finite JSON value")


def _load(path: Path):
    if not path.is_file():
        raise AuditError("expected a regular JSON file")
    try:
        with path.open("rb") as file:
            raw = file.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise AuditError("JSON input exceeds the 8 MiB limit")
        return json.loads(raw, object_pairs_hook=_object, parse_constant=_invalid_constant)
    except AuditError:
        raise
    except (OSError, ValueError, RecursionError) as exc:
        raise AuditError("could not read valid JSON") from exc


def _keys(obj, allowed, required=()):
    if not isinstance(obj, dict) or set(obj) - set(allowed) or not set(required) <= set(obj):
        raise AuditError("unexpected or missing object fields")


def _path(root: Path, value) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise AuditError("snapshot paths must be relative to the manifest directory")
    path = (root / value).resolve()
    if not path.is_relative_to(root):
        raise AuditError("snapshot path escapes the manifest directory")
    return path


def _tools(path: Path) -> tuple[set[str], list[ToolDef]]:
    data = _load(path)
    if not isinstance(data, dict) or not data:
        raise AuditError("expected a nonempty server map")
    servers = {path.stem: data} if isinstance(data.get("tools"), list) else data
    tools = []
    for server, block in sorted(servers.items()):
        items = block.get("tools") if isinstance(block, dict) else block
        if not server.strip() or not isinstance(items, list):
            raise AuditError("expected named servers with tool lists")
        names = set()
        for raw in items:
            if not isinstance(raw, dict):
                raise AuditError("expected tool objects")
            name = raw.get("name")
            if not isinstance(name, str) or not name.strip() or name in names:
                raise AuditError("missing or duplicate tool name within a server")
            if not isinstance(raw.get("description", ""), str):
                raise AuditError("tool description must be a string")
            for field in ("inputSchema", "input_schema"):
                if field in raw and not isinstance(raw[field], dict):
                    raise AuditError("tool input schema must be an object")
            names.add(name)
            tools.append(ToolDef.from_mcp(server, raw))
            if len(tools) > MAX_TOOLS:
                raise AuditError("snapshot exceeds the tool count limit")
    return set(servers), tools


def _fingerprint(finding: Finding) -> str:
    # Keep values out of the report, but distinguish rewritten evidence at the same location.
    parts = [finding.server, finding.tool, finding.rule_id, finding.location, finding.evidence]
    return hashlib.sha256(json.dumps(parts, ensure_ascii=True).encode("ascii")).hexdigest()


def _findings(tools: list[ToolDef]) -> dict[str, Finding]:
    result: dict[str, Finding] = {}
    for finding in engine.scan_tools(tools):
        key = _fingerprint(finding)
        if key not in result or result[key].confidence < finding.confidence:
            result[key] = finding
    return result


def _policy(raw) -> dict:
    _keys(raw, ("minimum_severity", "gate", "max_violations", "max_tool_changes"))
    policy = {"minimum_severity": "warning", "gate": "all", "max_violations": 0, **raw}
    if policy["minimum_severity"] not in tuple(SEVERITY_ORDER):
        raise AuditError("policy minimum_severity must be info, warning, or critical")
    if policy["gate"] not in ("all", "new"):
        raise AuditError("policy gate must be all or new")
    budget = policy["max_violations"]
    if type(budget) is not int or budget < 0:
        raise AuditError("policy max_violations must be a nonnegative integer")
    if "max_tool_changes" in policy and (type(policy["max_tool_changes"]) is not int
                                         or policy["max_tool_changes"] < 0):
        raise AuditError("policy max_tool_changes must be a nonnegative integer")
    return policy


def _project(root: Path, raw: dict, policy: dict) -> dict:
    current_path = _path(root, raw["snapshot"])
    current_servers, current = _tools(current_path)
    baseline_defined = "baseline" in raw
    if baseline_defined:
        baseline_path = _path(root, raw["baseline"])
        if baseline_path == current_path:
            raise AuditError("snapshot and baseline must be separate files")
        baseline_servers, baseline = _tools(baseline_path)
    elif policy["gate"] == "new":
        raise AuditError("gate=new requires an explicit baseline for every project")
    elif "max_tool_changes" in policy:
        raise AuditError("max_tool_changes requires an explicit baseline for every project")
    else:
        baseline_servers, baseline = set(), []

    try:
        previous, present = _findings(baseline), _findings(current)
        drift = snapshot.compare(baseline, current, baseline_servers, current_servers) if baseline_defined else None
    except RecursionError as exc:
        raise AuditError("snapshot schema nesting exceeds scanner limits") from exc
    severity_threshold = SEVERITY_ORDER[policy["minimum_severity"]]
    counts: Counter[str] = Counter()
    rows = []
    for key, now in sorted(present.items(), key=lambda pair: (
            pair[1].server, pair[1].tool, pair[1].location, pair[1].rule_id, pair[0])):
        prior = previous.get(key)
        rank = SEVERITY_ORDER[now.severity]
        status = ("unbaselined" if not baseline_defined else "new" if prior is None else
                  "escalated" if rank > SEVERITY_ORDER[prior.severity] else "existing")
        gated = rank >= severity_threshold and (policy["gate"] == "all" or status in ("new", "escalated"))
        counts[status] += 1
        counts["violations"] += gated
        rows.append({"server": now.server, "tool": now.tool, "location": now.location,
                     "rule_id": now.rule_id, "severity": now.severity, "status": status,
                     "policy_violation": gated})
    return {"id": raw["id"], "tools_scanned": len(current),
            "servers_scanned": len(current_servers), "has_baseline": baseline_defined,
            "metadata_drift": drift,
            "resolved_findings": len(previous.keys() - present.keys()),
            "policy_violations": counts["violations"], "findings": rows}


def audit(manifest: Path) -> dict:
    manifest = manifest.resolve()
    data = _load(manifest)
    _keys(data, ("version", "policy", "projects"), ("version", "projects"))
    if type(data["version"]) is not int or data["version"] != 1:
        raise AuditError("unsupported manifest version; expected 1")
    policy = _policy(data.get("policy", {}))
    projects = data["projects"]
    if not isinstance(projects, list) or not 1 <= len(projects) <= MAX_PROJECTS:
        raise AuditError("expected between 1 and 100 projects")
    ids = set()
    results = []
    for raw in projects:
        _keys(raw, ("id", "snapshot", "baseline"), ("id", "snapshot"))
        name = raw["id"]
        if not isinstance(name, str) or not PROJECT_ID.fullmatch(name) or name in ids:
            raise AuditError("invalid or duplicate project ID")
        ids.add(name)
        try:
            results.append(_project(manifest.parent, raw, policy))
        except AuditError as exc:
            raise AuditError(f"{name}: {exc}") from exc
    results.sort(key=lambda project: project["id"])
    total = sum(p["policy_violations"] for p in results)
    tool_changes = sum(len(p["metadata_drift"]["tools"]) for p in results if p["metadata_drift"] is not None)
    passed = total <= policy["max_violations"]
    if "max_tool_changes" in policy:
        passed = passed and tool_changes <= policy["max_tool_changes"]
    return {"version": 1, "policy": policy, "passed": passed,
            "summary": {"projects": len(results), "tools_scanned": sum(p["tools_scanned"] for p in results),
                        "policy_violations": total, "tool_changes": tool_changes,
                        "resolved_findings": sum(p["resolved_findings"] for p in results)},
            "projects": results}


def to_text(report: dict) -> str:
    summary = report["summary"]
    status = "PASS" if report["passed"] else "FAIL"
    lines = [f"{status}: {summary['projects']} projects, {summary['tools_scanned']} tools, "
             f"{summary['policy_violations']} policy violations (budget {report['policy']['max_violations']})."]
    if "max_tool_changes" in report["policy"]:
        lines.append(f"{summary['tool_changes']} changed tools (budget {report['policy']['max_tool_changes']}).")
    for project in report["projects"]:
        lines.append(f"{project['id']}: {project['tools_scanned']} tools, "
                     f"{project['policy_violations']} violations, {project['resolved_findings']} resolved")
        for finding in project["findings"]:
            if finding["policy_violation"]:
                target = json.dumps(f"{finding['server']}/{finding['tool']}")
                location = json.dumps(finding["location"])
                lines.append(f"  {finding['severity']} {finding['status']} {finding['rule_id']}: {target} at {location}")
    return "\n".join(lines)
