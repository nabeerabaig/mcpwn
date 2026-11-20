from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


def severity_for(confidence: float) -> str:
    if confidence >= 0.8:
        return "critical"
    if confidence >= 0.5:
        return "warning"
    return "info"


@dataclass
class Finding:
    rule_id: str
    tier: int
    title: str
    message: str
    confidence: float
    server: str = ""
    tool: str = ""
    location: str = ""  # e.g. description, inputSchema.properties.x.enum[1]
    source: str = ""  # config file or scanned file path
    evidence: str = ""
    severity: str = ""

    def __post_init__(self) -> None:
        self.confidence = round(max(0.0, min(1.0, self.confidence)), 2)
        if not self.severity:
            self.severity = severity_for(self.confidence)

    def rescore(self, confidence: float) -> None:
        self.confidence = round(max(0.0, min(1.0, confidence)), 2)
        self.severity = severity_for(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolDef:
    server: str
    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)
    source: str = ""

    @classmethod
    def from_mcp(cls, server: str, raw: dict, source: str = "") -> "ToolDef":
        return cls(
            server=server,
            name=str(raw.get("name", "")),
            description=str(raw.get("description", "") or ""),
            input_schema=raw.get("inputSchema") or raw.get("input_schema") or {},
            source=source,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


@dataclass
class ServerSpec:
    name: str
    command: str
    args: list = field(default_factory=list)
    env: dict = field(default_factory=dict)
    source: str = ""
    transport: str = "stdio"
    url: Optional[str] = None
    headers: dict = field(default_factory=dict)
