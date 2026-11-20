"""Tier 1: fast, high-precision structural detectors."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

from .models import Finding

HIDDEN_CODEPOINTS = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE / BOM",
    0x00AD: "SOFT HYPHEN",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
}


def _is_hidden(ch: str) -> str | None:
    cp = ord(ch)
    if cp in HIDDEN_CODEPOINTS:
        return HIDDEN_CODEPOINTS[cp]
    if 0xE0000 <= cp <= 0xE007F:
        return "UNICODE TAG CHARACTER"
    if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
        return "BIDI CONTROL"
    if 0xFE00 <= cp <= 0xFE0F:
        return "VARIATION SELECTOR"
    return None


def decode_tag_chars(text: str) -> str:
    """Unicode tag characters (U+E0020..E007E) smuggle ASCII invisibly."""
    out = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


OVERRIDE_PATTERNS = [
    (r"\b(ignore|disregard|forget|override)\b[^.\n]{0,30}\b(previous|prior|above|earlier|all|any)\b[^.\n]{0,30}\b(instructions?|prompts?|rules|directions?|context)\b", "instruction-override", 0.9),
    (r"\byou (are|will) now\b[^.\n]{0,40}\b(act|behave|operate|function|an?|the)\b", "role-reassignment", 0.6),
    (r"\bnew (system )?(instructions?|prompt|rules)\s*:", "new-instructions", 0.85),
    (r"</?\s*(important|system|instructions?|admin|override)\s*>", "pseudo-tag", 0.7),
    (r"\[\s*(system|admin|override)\s*\]", "pseudo-tag", 0.6),
    (r"\bdo not\b[^.\n]{0,40}\b(tell|inform|mention|reveal|notify|alert|show)\b[^.\n]{0,40}\b(the )?(user|human|operator)\b", "concealment", 0.9),
    (r"\b(without|never)\b[^.\n]{0,30}\b(telling|informing|notifying|mention(ing)?( to)?|reveal(ing)?( to)?)\b[^.\n]{0,20}\b(the )?(user|human)\b", "concealment", 0.9),
    (r"\btreat\b[^.\n]{0,40}\b(returned|output|result|response)s?\b[^.\n]{0,40}\bas (a |an )?(command|instruction|order)s?\b", "trust-escalation", 0.75),
    (r"\b(this|these) (is|are) (a )?(mandatory|required)\b[^.\n]{0,40}\bdo not (ask|confirm|question)\b", "confirmation-bypass", 0.7),
]

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])")
_SUSPICIOUS_DECODED = re.compile(
    r"(ignore|instruction|system prompt|curl |wget |bash|/bin/sh|ssh|passw|secret|token|exfil|http://|https://|eval\(|exec\()",
    re.I,
)


def scan_text(text: str, *, tool: str = "", server: str = "", location: str = "", source: str = "") -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings

    def mk(rule, title, msg, conf, evidence=""):
        return Finding(
            rule_id=rule, tier=1, title=title, message=msg, confidence=conf,
            server=server, tool=tool, location=location, source=source,
            evidence=evidence[:200],
        )

    # hidden unicode
    hidden: dict[str, int] = {}
    for ch in text:
        name = _is_hidden(ch)
        if name:
            hidden[name] = hidden.get(name, 0) + 1
    if hidden:
        total = sum(hidden.values())
        kinds = ", ".join(f"{k} x{v}" for k, v in hidden.items())
        smuggled = decode_tag_chars(text)
        conf = 0.95 if (smuggled or total >= 3) else 0.75
        msg = f"Invisible characters found ({kinds})."
        if smuggled:
            msg += f" Decoded hidden text: {smuggled[:120]!r}"
        findings.append(mk("T1-HIDDEN-UNICODE", "Hidden Unicode characters", msg, conf, smuggled))
        if smuggled:
            findings.extend(scan_text(smuggled, tool=tool, server=server, location=location + "#hidden", source=source))

    # override phrases
    lowered = unicodedata.normalize("NFKC", text)
    for pat, name, conf in OVERRIDE_PATTERNS:
        m = re.search(pat, lowered, re.I)
        if m:
            findings.append(mk(f"T1-{name.upper()}", f"Injection phrase: {name}",
                               f"Text matches '{name}' pattern.", conf, m.group(0)))

    # base64 payloads
    for m in _B64_RE.finditer(text):
        blob = m.group(1)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if not decoded or sum(c.isprintable() or c in "\n\t" for c in decoded) / len(decoded) < 0.95:
            continue
        if _SUSPICIOUS_DECODED.search(decoded):
            findings.append(mk("T1-BASE64-PAYLOAD", "Base64-encoded instruction payload",
                               "Base64 blob decodes to text containing instruction/exfiltration keywords.", 0.9, decoded))
            findings.extend(scan_text(decoded, tool=tool, server=server, location=location + "#b64", source=source)[:3])
        elif len(decoded) >= 24 and " " in decoded:
            findings.append(mk("T1-BASE64-TEXT", "Base64-encoded readable text",
                               "Opaque base64 blob that decodes to prose; unusual in a tool definition.", 0.55, decoded))
    return findings
