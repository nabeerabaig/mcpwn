"""Phase 5: agent config / instruction file scanning (.cursorrules, CLAUDE.md, copilot-instructions, ...)."""
from __future__ import annotations

import re
from pathlib import Path

from . import tier1, tier2
from .models import Finding

PATTERNS = [
    ".cursorrules", ".windsurfrules", "CLAUDE.md", "AGENTS.md", "GEMINI.md",
    ".github/copilot-instructions.md", ".github/instructions/*.md",
    ".github/ISSUE_TEMPLATE/*", ".github/PULL_REQUEST_TEMPLATE*", ".github/pull_request_template*",
    ".cursor/rules/*", ".claude/commands/*.md", ".claude/agents/*.md",
    ".clinerules", ".roo/rules/*", ".continuerules",
]

SHELL_DIRECTIVE = re.compile(
    r"(?:\b(always|must|should|first|before|automatically|silently)\b[^.\n]{0,80})?"
    r"(`[^`\n]*\b(curl|wget|nc|ncat|bash|sh|powershell|python -c|node -e|eval|base64 -d)\b[^`\n]*`|"
    r"\b(curl|wget)\b[^\n]*\|\s*(ba)?sh\b)", re.I)
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
MD_LINK_REF = re.compile(r"^\s*\[[^\]]+\]:\s*#\s*\((.*?)\)", re.M)  # hidden markdown comment trick
AUTO_APPROVE = re.compile(r"\b(auto[- ]?approve|without (asking|confirmation|approval)|never ask (for )?(confirmation|permission)|"
                          r"disable (the )?(safety|confirmation)|--dangerously-skip-permissions|yolo mode)\b", re.I)


def find_files(root: Path) -> list[Path]:
    found: dict[Path, None] = {}
    for pat in PATTERNS:
        for p in root.glob(pat):
            if p.is_file():
                found[p] = None
    return sorted(found)


def scan_file(path: Path, root: Path | None = None) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = str(path.relative_to(root)) if root and path.is_relative_to(root) else str(path)
    ctx = dict(server="repo", tool=path.name, source=rel)
    out: list[Finding] = []
    out.extend(tier1.scan_text(text, location="file", **ctx))
    out.extend(tier2.scan_text(text, location="file", **ctx))

    def mk(rule, title, msg, conf, ev=""):
        return Finding(rule, 5, title, msg, conf, location="file", evidence=ev.strip()[:200], **ctx)

    m = SHELL_DIRECTIVE.search(text)
    if m:
        piped = bool(re.search(r"\|\s*(ba)?sh\b", m.group(0)))
        out.append(mk("T5-SHELL-IN-RULES", "Shell command embedded in agent rules",
                      "Agent instruction file embeds a shell command the agent may be induced to run (AIShellJack pattern).",
                      0.85 if piped else 0.6, m.group(0)))
    for cm in list(HTML_COMMENT.finditer(text)) + list(MD_LINK_REF.finditer(text)):
        body = cm.group(1)
        inner = tier1.scan_text(body, location="hidden-comment", **ctx) + tier2.scan_text(body, location="hidden-comment", **ctx)
        directive = tier2.DIRECTIVE.search(body) and len(body.split()) >= 6
        if inner or directive:
            conf = max([f.confidence for f in inner] + [0.6 if directive else 0.0])
            out.append(mk("T5-HIDDEN-COMMENT-INSTRUCTION", "Instructions hidden in a markdown/HTML comment",
                          "Comments are invisible when rendered but read by agents; this one contains directive text.",
                          conf, body))
    am = AUTO_APPROVE.search(text)
    if am:
        out.append(mk("T5-APPROVAL-BYPASS", "Rules weaken human confirmation",
                      "File instructs the agent to skip approvals/confirmation.", 0.55, am.group(0)))
    from .engine import dedupe
    return dedupe(out)


def scan_repo(root: Path) -> tuple[list[Finding], list[Path]]:
    files = find_files(root)
    findings: list[Finding] = []
    for p in files:
        findings.extend(scan_file(p, root))
    return findings, files


def security_score(findings: list[Finding]) -> int:
    """0-100, higher is safer. Weighted by confidence, diminishing returns per finding."""
    penalty = 0.0
    weights = {"critical": 22, "warning": 8, "info": 1}
    for f in findings:
        penalty += weights[f.severity] * f.confidence
    return max(0, round(100 - min(100, penalty)))
