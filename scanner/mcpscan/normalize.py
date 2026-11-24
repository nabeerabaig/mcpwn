"""Bounded, evidence-preserving text normalization for detector inputs."""
from __future__ import annotations

from dataclasses import dataclass
import unicodedata

MAX_NORMALIZE_CHARS = 1_000_000
MAX_RECORDED_CHARACTERS = 100


@dataclass(frozen=True)
class NormalizedText:
    original: str
    normalized: str | None
    transformed: bool
    suspicious_characters: tuple[dict, ...]
    status: str
    reason: str = ""


def normalize_text(value: object) -> NormalizedText:
    """Return NFKC analysis text while retaining the exact original input."""
    if not isinstance(value, str):
        return NormalizedText("", None, False, (), "unsupported", "input is not text")
    if len(value) > MAX_NORMALIZE_CHARS:
        return NormalizedText(value, None, False, (), "unsupported",
                              f"text exceeds {MAX_NORMALIZE_CHARS} character limit")
    suspicious = []
    for index, char in enumerate(value):
        category = unicodedata.category(char)
        if category in {"Cf", "Cs", "Co"}:
            suspicious.append({
                "index": index,
                "codepoint": f"U+{ord(char):04X}",
                "name": unicodedata.name(char, "UNNAMED"),
                "category": category,
            })
            if len(suspicious) >= MAX_RECORDED_CHARACTERS:
                break
    normalized = unicodedata.normalize("NFKC", value)
    return NormalizedText(value, normalized, normalized != value, tuple(suspicious), "ok")
