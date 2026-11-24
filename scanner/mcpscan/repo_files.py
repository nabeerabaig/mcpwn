"""Context-aware scanning of supported agent instruction and skill files."""
from __future__ import annotations

import re
from pathlib import Path

from . import tier1, tier2
from .engine import dedupe
from .models import Finding
from .normalize import normalize_text

MAX_REPO_FILE_BYTES = 1_000_000
TEXT_EXTENSIONS = {
    ".md", ".mdc", ".txt", ".toml", ".yaml", ".yml", ".json", ".jsonc",
    ".ini", ".rules", ".agent", ".prompt",
}
EXTENSIONLESS_FILES = {".cursorrules", ".windsurfrules", ".continuerules"}

PATTERNS = [
    ".cursorrules", ".windsurfrules", "CLAUDE.md", "AGENTS.md", "AGENTS.override.md",
    "GEMINI.md", "SKILL.md", ".continuerules",
    ".github/copilot-instructions.md", ".github/instructions/*.md", ".github/instructions/*.instructions.md",
    ".github/agents/*.agent.md", ".github/prompts/*.prompt.md",
    ".github/ISSUE_TEMPLATE/*", ".github/PULL_REQUEST_TEMPLATE*",
    ".github/pull_request_template*", ".cursor/rules/*", ".cursor/skills/**/SKILL.md",
    ".claude/commands/*.md", ".claude/agents/*.md", ".claude/skills/**/SKILL.md",
    ".agents/skills/**/SKILL.md", ".codex/skills/**/SKILL.md", ".opencode/skills/**/SKILL.md",
    ".gemini/skills/**/SKILL.md", "skills/**/SKILL.md",
    ".gemini/commands/**/*.toml",
    ".opencode/agents/*.md", ".opencode/commands/*.md", ".opencode/agent/*.md",
    ".opencode/command/*.md", ".opencode/rules/*.md",
    ".clinerules", ".roo/rules/*", ".windsurf/rules/*", ".continue/rules/*",
]

SHELL_DIRECTIVE = re.compile(
    r"(?:\b(always|must|should|first|before|automatically|silently)\b[^.\n]{0,80})?"
    r"(`[^`\n]*\b(curl|wget|nc|ncat|bash|sh|powershell|python -c|node -e|eval|base64 -d)\b[^`\n]*`|"
    r"\b(curl|wget)\b[^\n]*\|\s*(ba)?sh\b)", re.I)
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
MD_LINK_REF = re.compile(r"^\s*\[[^\]]+\]:\s*#\s*\\((.*?)\\)", re.M)
AUTO_APPROVE = re.compile(r"\b(auto[- ]?approve|without (asking|confirmation|approval)|never ask (for )?(confirmation|permission)|"
                          r"disable (the )?(safety|confirmation)|--dangerously-skip-permissions|yolo mode)\b", re.I)


def find_files(root: Path) -> list[Path]:
    found: dict[Path, None] = {}
    for pattern in PATTERNS:
        for candidate in root.glob(pattern):
            if candidate.is_file():
                found[candidate] = None
    return sorted(found)


def _content_type(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in TEXT_EXTENSIONS:
        return suffix[1:] or "text"
    if path.name.lower() in EXTENSIONLESS_FILES:
        return "agent_rules_text"
    return None


def _scan_decoded_text(text: str, path: Path, relative: str) -> list[Finding]:
    ctx = dict(server="repo", tool=path.name, source=relative)
    out: list[Finding] = []
    out.extend(tier1.scan_text(text, location="file", **ctx))
    out.extend(tier2.scan_text(text, location="file", **ctx))

    def make(rule: str, title: str, message: str, confidence: float, evidence: str = "") -> Finding:
        return Finding(rule, 5, title, message, confidence, location="file",
                       evidence=evidence.strip()[:200], **ctx)

    match = SHELL_DIRECTIVE.search(text)
    if match:
        piped = bool(re.search(r"\|\s*(ba)?sh\b", match.group(0)))
        out.append(make(
            "T5-SHELL-IN-RULES", "Shell command embedded in agent rules",
            "Agent instruction file embeds a shell command the agent may be induced to run (AIShellJack pattern).",
            0.85 if piped else 0.6, match.group(0)
        ))
    for comment in list(HTML_COMMENT.finditer(text)) + list(MD_LINK_REF.finditer(text)):
        body = comment.group(1)
        hidden = (tier1.scan_text(body, location="hidden-comment", **ctx)
                  + tier2.scan_text(body, location="hidden-comment", **ctx))
        directive = tier2.DIRECTIVE.search(body) and len(body.split()) >= 6
        if hidden or directive:
            confidence = max([finding.confidence for finding in hidden] + [0.6 if directive else 0.0])
            out.append(make(
                "T5-HIDDEN-COMMENT-INSTRUCTION",
                "Instructions hidden in a markdown/HTML comment",
                "Comments are invisible when rendered but read by agents; this one contains directive text.",
                confidence, body
            ))
    auto_approval = AUTO_APPROVE.search(text)
    if auto_approval:
        out.append(make(
            "T5-APPROVAL-BYPASS", "Rules weaken human confirmation",
            "File instructs the agent to skip approvals or confirmation.",
            0.55, auto_approval.group(0)
        ))
    return dedupe(out)


def scan_file_with_coverage(path: Path, root: Path | None = None) -> tuple[list[Finding], dict]:
    relative = str(path.relative_to(root)) if root and path.is_relative_to(root) else str(path)
    record = {
        "source_type": "agent_instruction_file",
        "source_id": relative,
        "content_type": _content_type(path) or "unsupported_file_type",
        "status": "failed",
        "fields_discovered": 1,
        "fields_scanned": 0,
        "fields_skipped": [],
        "unsupported_fields": [],
        "scan_errors": [],
        "detectors_applied": [],
        "normalization_applied": False,
        "suspicious_unicode": [],
    }
    content_type = _content_type(path)
    if content_type is None:
        issue = {"location": "file", "reason": f"unsupported instruction-file extension: {path.suffix or '(none)'}"}
        record.update(status="unsupported", fields_skipped=[issue], unsupported_fields=[issue])
        return [], record

    try:
        raw = path.read_bytes()
    except OSError as exc:
        record["scan_errors"].append(type(exc).__name__)
        record["fields_skipped"].append({"location": "file", "reason": f"read failed: {type(exc).__name__}"})
        return [], record

    if len(raw) > MAX_REPO_FILE_BYTES:
        issue = {"location": "file", "reason": f"file exceeds {MAX_REPO_FILE_BYTES}-byte scan limit"}
        record.update(status="unsupported", fields_skipped=[issue], unsupported_fields=[issue])
        return [], record

    try:
        text = raw.decode("utf-8-sig", "strict")
    except UnicodeDecodeError:
        record["scan_errors"].append("UnicodeDecodeError")
        record["fields_skipped"].append({"location": "file", "reason": "file is not valid UTF-8"})
        return [], record

    if "\x00" in text:
        issue = {"location": "file", "reason": "NUL byte detected; binary content is not scanned"}
        record.update(status="unsupported", fields_skipped=[issue], unsupported_fields=[issue])
        return [], record

    if not text:
        record.update(status="not_applicable",
                      fields_skipped=[{"location": "file", "reason": "empty file"}])
        return [], record

    try:
        findings = _scan_decoded_text(text, path, relative)
        record["detectors_applied"] = ["tier1", "tier2", "tier5"]
        normalized = normalize_text(text)
        if normalized.status == "ok":
            record["suspicious_unicode"] = [
                {"location": "file", **character} for character in normalized.suspicious_characters
            ]
            if normalized.transformed and normalized.normalized is not None:
                record["normalization_applied"] = True
                normalized_findings = _scan_decoded_text(normalized.normalized, path, relative + "#nfkc")
                for finding in normalized_findings:
                    finding.evidence = text[:200]
                    finding.message += " Detected in an NFKC-normalized representation; original file evidence is retained."
                findings.extend(normalized_findings)
                record["detectors_applied"].append("nfkc-normalized-review")
        else:
            issue = {"location": "file", "reason": normalized.reason or "normalization unsupported"}
            record["fields_skipped"].append(issue)
            record["unsupported_fields"].append(issue)
            record["status"] = "partially_scanned"
        record["fields_scanned"] = 1
        if record["status"] != "partially_scanned":
            record["status"] = "fully_scanned"
        return dedupe(findings), record
    except (RecursionError, RuntimeError, TypeError, ValueError) as exc:
        record["scan_errors"].append(type(exc).__name__)
        record["status"] = "failed"
        record["fields_skipped"].append({"location": "file", "reason": f"detector failed: {type(exc).__name__}"})
        return [], record


def scan_file(path: Path, root: Path | None = None) -> list[Finding]:
    """Backward-compatible findings-only wrapper."""
    return scan_file_with_coverage(path, root)[0]


def scan_repo_with_coverage(root: Path) -> tuple[list[Finding], list[Path], list[dict]]:
    files = find_files(root)
    findings: list[Finding] = []
    coverage: list[dict] = []
    for path in files:
        found, record = scan_file_with_coverage(path, root)
        findings.extend(found)
        coverage.append(record)
    return findings, files, coverage


def scan_repo(root: Path) -> tuple[list[Finding], list[Path]]:
    """Backward-compatible repository scan."""
    findings, files, _coverage = scan_repo_with_coverage(root)
    return findings, files


def security_score(findings: list[Finding]) -> int:
    """0-100, higher is safer. Weighted by confidence, diminishing returns per finding."""
    penalty = 0.0
    weights = {"critical": 22, "warning": 8, "info": 1}
    for finding in findings:
        penalty += weights[finding.severity] * finding.confidence
    return max(0, round(100 - min(100, penalty)))
