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
    if unicodedata.category(ch) == "Cf":
        return unicodedata.name(ch, "FORMAT CONTROL")
    return None


def decode_tag_chars(text: str) -> str:
    """Unicode tag characters (U+E0020..E007E) smuggle ASCII invisibly."""
    out = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


_GAP = r"[^.]{0,40}"
OVERRIDE_PATTERNS = [
    (rf"\b(ignore|disregard|forget|override)\b{_GAP}\b(previous|prior|above|earlier|all|any)\b{_GAP}\b(instructions?|prompts?|rules|directions?|context)\b", "instruction-override", 0.9),
    (rf"\b(this|these|document|configuration|file)\b{_GAP}\b(claims?|has|takes?|is)\b{_GAP}\b(priority|precedence|authority|authoritative)\b", "authority-override", 0.85),
    (rf"\b(priority|precedence|authority)\b{_GAP}\b(over|above)\b{_GAP}\b(other|existing|previous|all)\b{_GAP}\b(guidelines?|instructions?|rules|policies)\b", "authority-override", 0.85),
    (rf"\b(elevated|higher|system|administrator|admin)\b{_GAP}\b(priority|authority|privilege)\b", "authority-override", 0.75),
    (rf"\byou (are|will) now\b{_GAP}\b(act|behave|operate|function|an?|the)\b", "role-reassignment", 0.6),
    (r"\bnew (system )?(instructions?|prompt|rules)\s*:", "new-instructions", 0.85),
    (r"</?\s*(important|system|instructions?|admin|override)\s*>", "pseudo-tag", 0.7),
    (r"\[\s*(system|admin|override)\s*\]", "pseudo-tag", 0.6),
    (rf"\bdo not\b{_GAP}\b(tell|inform|mention|reveal|notify|alert|show|disclose)\b{_GAP}\b(the )?(user|human|operator)\b", "concealment", 0.9),
    (rf"\b(without|never)\b{_GAP}\b(telling|informing|notifying|mention(ing)?( to)?|reveal(ing)?( to)?)\b{_GAP}\b(the )?(user|human)\b", "concealment", 0.9),
    (rf"\b(keep|make|leave)\b{_GAP}\b(hidden|secret|confidential|undisclosed)\b{_GAP}\b(from the user|to the user|user)\b", "concealment", 0.85),
    (rf"\btreat\b{_GAP}\b(returned|output|result|response)s?\b{_GAP}\bas (a |an )?(command|instruction|order)s?\b", "trust-escalation", 0.75),
    (rf"\b(this|these) (is|are) (a )?(mandatory|required)\b{_GAP}\bdo not (ask|confirm|question)\b", "confirmation-bypass", 0.7),
]

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{24,})(?![0-9A-Fa-f])")
_SUSPICIOUS_DECODED = re.compile(
    r"(ignore|disregard|instruction|system prompt|priority|guidelines|conceal|hidden|curl |wget |bash|/bin/sh|ssh|passw|secret|token|exfil|http://|https://|eval\(|exec\()",
    re.I,
)


def _printable_text(decoded: str) -> bool:
    return bool(decoded) and sum(c.isprintable() or c in "\n\t" for c in decoded) / len(decoded) >= 0.95


def scan_text(text: str, *, tool: str = "", server: str = "", location: str = "", source: str = "") -> list[Finding]:
    findings: list[Finding] = []
    if not text:
    
    # Hex payloads: decode only bounded, even-length, printable UTF-8 candidates.
    for m in _HEX_RE.finditer(text):
        blob = m.group(1)
        if len(blob) % 2:
            continue
        try:
            decoded = bytes.fromhex(blob).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if not _printable_text(decoded) or not _SUSPICIOUS_DECODED.search(decoded):
            continue
        findings.append(mk("T1-HEX-PAYLOAD", "Hex-encoded instruction payload",
                           "Hexadecimal content decodes to text containing instruction/security keywords.",
                           0.9, blob))
        decoded_findings = scan_text(decoded, tool=tool, server=server,
                                      location=location + "#hex", source=source)[:3]
        for finding in decoded_findings:
            finding.evidence = blob
            finding.message += " Detected in decoded hexadecimal content; original encoded evidence is preserved."
        findings.extend(decoded_findings)
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
        findings.append(mk("T1-HIDDEN-UNICODE", "Hidden Unicode characters", msg, conf, text[:200]))
        if smuggled:
            decoded_findings = scan_text(smuggled, tool=tool, server=server,
                                          location=location + "#hidden", source=source)
            for finding in decoded_findings:
                finding.evidence = text[:200]
                finding.message += " Detected in hidden Unicode-decoded text; original source evidence is preserved."
            findings.extend(decoded_findings)

    # override phrases
    lowered = unicodedata.normalize("NFKC", text)
    analysis = "".join(ch for ch in lowered if unicodedata.category(ch) != "Cf")
    analysis = re.sub(r"\s+", " ", analysis)
    for pat, name, conf in OVERRIDE_PATTERNS:
        m = re.search(pat, analysis, re.I)
        if m:
            matched = m.group(0)
            original_evidence = matched if matched in text else text[:200]
            note = " Text was matched after NFKC normalization." if matched not in text else ""
            findings.append(mk(f"T1-{name.upper()}", f"Injection phrase: {name}",
                               f"Text matches '{name}' pattern.{note}", conf, original_evidence))

    # Base64 payloads
    for m in _B64_RE.finditer(text):
        blob = m.group(1)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if not _printable_text(decoded):
            continue
        if _SUSPICIOUS_DECODED.search(decoded):
            findings.append(mk("T1-BASE64-PAYLOAD", "Base64-encoded instruction payload",
                               "Base64 blob decodes to text containing instruction/exfiltration keywords.", 0.9, blob))
            decoded_findings = scan_text(decoded, tool=tool, server=server,
                                          location=location + "#b64", source=source)[:3]
            for finding in decoded_findings:
                finding.evidence = blob
                finding.message += " Detected in decoded base64 content; original encoded evidence is preserved."
            findings.extend(decoded_findings)
        elif len(decoded) >= 24 and " " in decoded:
            findings.append(mk("T1-BASE64-TEXT", "Base64-encoded readable text",
                               "Opaque base64 blob that decodes to prose; unusual in a tool definition.", 0.55, blob))
    return findings
