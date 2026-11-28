"""Bounded, evidence-preserving Unicode normalization for detector inputs.

The scanner keeps the original text for evidence and builds a separate analysis
view. The analysis view is intentionally conservative: NFKC compatibility
normalization, removal of invisible formatting controls, and a small set of
high-confidence Cyrillic/Greek lookalikes commonly used to disguise Latin
security phrases. It is never used to rewrite or execute source content.
"""
from __future__ import annotations

from dataclasses import dataclass
import unicodedata

MAX_NORMALIZE_CHARS = 1_000_000
MAX_RECORDED_CHARACTERS = 100

# Common homoglyphs that visually resemble Latin letters in ASCII attack text.
# This is not a complete Unicode confusables database; it is a bounded heuristic.
_CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O",
    "р": "p", "Р": "P", "с": "c", "С": "C", "х": "x", "Х": "X",
    "у": "y", "У": "Y", "і": "i", "І": "I", "ј": "j", "Ј": "J",
    "к": "k", "К": "K", "м": "m", "М": "M", "т": "t", "Т": "T",
    "в": "b", "В": "B", "н": "h", "Н": "H", "ѕ": "s", "Ѕ": "S",
    "ԁ": "d", "ԛ": "q",
    # Greek
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X", "α": "a", "ο": "o", "ρ": "p", "ι": "i",
    "κ": "k", "ν": "v", "τ": "t", "υ": "y", "χ": "x",
})


@dataclass(frozen=True)
class NormalizedText:
    original: str
    normalized: str | None
    transformed: bool
    suspicious_characters: tuple[dict, ...]
    status: str
    reason: str = ""
    analysis_text: str | None = None
    obfuscation_transformed: bool = False


def _is_invisible_format(char: str) -> bool:
    cp = ord(char)
    category = unicodedata.category(char)
    return (
        category == "Cf"
        or cp in {0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5}
        or 0xFE00 <= cp <= 0xFE0F
        or 0xE0100 <= cp <= 0xE01EF
    )


def normalize_text(value: object) -> NormalizedText:
    """Return normalized analysis text while retaining exact original input."""
    if not isinstance(value, str):
        return NormalizedText("", None, False, (), "unsupported", "input is not text")
    if len(value) > MAX_NORMALIZE_CHARS:
        return NormalizedText(value, None, False, (), "unsupported",
                              f"text exceeds {MAX_NORMALIZE_CHARS} character limit")

    suspicious = []
    for index, char in enumerate(value):
        category = unicodedata.category(char)
        if category in {"Cf", "Cs", "Co", "Zl", "Zp"} or _is_invisible_format(char):
            suspicious.append({
                "index": index,
                "codepoint": f"U+{ord(char):04X}",
                "name": unicodedata.name(char, "UNNAMED"),
                "category": category,
            })
            if len(suspicious) >= MAX_RECORDED_CHARACTERS:
                break

    normalized = unicodedata.normalize("NFKC", value)
    # Strip format controls only in the analysis copy. Original evidence is untouched.
    without_controls = "".join(char for char in normalized if not _is_invisible_format(char))
    confusable_view = without_controls.translate(_CONFUSABLES)
    obfuscation_transformed = confusable_view != without_controls or without_controls != normalized
    return NormalizedText(
        original=value,
        normalized=normalized,
        transformed=normalized != value,
        suspicious_characters=tuple(suspicious),
        status="ok",
        analysis_text=confusable_view,
        obfuscation_transformed=obfuscation_transformed,
    )
