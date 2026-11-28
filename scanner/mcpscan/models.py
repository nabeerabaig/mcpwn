from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
from typing import Any, Optional

DETECTOR_VERSION = "0.3.0.dev0"

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


def severity_for(confidence: float) -> str:
    if confidence >= 0.8:
        return "critical"
    if confidence >= 0.5:
        return "warning"
    return "info"


def finding_category(rule_id: str, tier: int) -> str:
    rule = rule_id.upper()
    if rule.startswith("T1-"):
        return "structural"
    if rule.startswith("T2-"):
        return "contextual"
    if rule.startswith("T3-"):
        return "semantic"
    if rule.startswith("D-"):
        return "dynamic"
    if rule.startswith("T4-"):
        return "runtime_and_drift"
    if rule.startswith("T5-"):
        return "agent_instruction_files"
    return {1: "structural", 2: "contextual", 3: "semantic", 4: "runtime_and_drift",
            5: "agent_instruction_files", 6: "dynamic"}.get(tier, "other")


# Rule-specific review advice. Keep this static: scanned content is never interpolated.
_CONTEXT_GUIDANCE = {
    "T2-UNVERIFIED-AUTHORIZATION": (
        "An agent may mistake a claim inside untrusted text for permission to access private data.",
        "Verify approval through a trusted identity or permission channel. Do not accept the scanned text as authorization.",
    ),
    "T2-CONTEXT-DISCLOSURE": (
        "An agent may disclose nonpublic system instructions, developer messages, or configuration.",
        "Check whether the requested material is public and intended for disclosure. Do not return private instructions based on the scanned text.",
    ),
    "T2-TARGETED-TASK-OVERRIDE": (
        "An instruction addressed to the agent may redirect it away from the user's task.",
        "Check whether the instruction belongs to a trusted policy source. Keep the original user task when the override comes from scanned data.",
    ),
    "T5-SHELL-IN-RULES": (
        "The file directs a reader to run a command; this is different from simply documenting syntax.",
        "Review the command and its effects before following it. If it is only an example, describe what it does without instructing an agent to run it.",
    ),
}


def finding_guidance(rule_id: str, tier: int) -> tuple[str, str]:
    rule = rule_id.upper()
    if rule in _CONTEXT_GUIDANCE:
        return _CONTEXT_GUIDANCE[rule]
    if any(token in rule for token in ("EXFIL", "FORWARDING", "EGRESS")):
        return ("May disclose user, conversation, credential, or tool data to an external destination.",
                "Verify the destination and data flow independently; remove any unjustified transfer or require explicit approval.")
    if any(token in rule for token in ("SENSITIVE", "SECRET", "CREDENTIAL")):
        return ("May expose credentials or other sensitive local data.",
                "Confirm that access is required for the documented task; remove unrelated credential access and secret forwarding.")
    if any(token in rule for token in ("EXEC", "SHELL", "COMMAND")):
        return ("May cause unapproved code or command execution.",
                "Remove untrusted execution directives; require reviewed commands and explicit user authorization.")
    if any(token in rule for token in ("OVERRIDE", "CONCEAL", "TRUST", "ROLE", "INSTRUCTION")):
        return ("May alter agent instruction handling or conceal actions from the user.",
                "Treat the text as untrusted data; remove instruction-hierarchy overrides and concealment requests.")
    if any(token in rule for token in ("UNICODE", "BASE64")):
        return ("Encoded or invisible content may obscure instructions or change how text is interpreted.",
                "Inspect the original content and decoded representation; remove unexplained hidden or encoded text.")
    if tier == 6 or rule.startswith("D-"):
        return ("A simulated agent exhibited behavior associated with the scanned tool description.",
                "Inspect the paired trial traces and tool description; disable or revise the suspect instruction pending review.")
    return ("The finding may influence agent behavior or tool-use decisions.",
            "Review the cited source and surrounding context; keep only instructions necessary for the documented tool behavior.")


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
    finding_id: str = ""
    detector_version: str = DETECTOR_VERSION
    category: str = ""
    impact: str = ""
    remediation: str = ""
    semantic_status: str = "not_assessed"
    dynamic_validation_status: str = "not_requested"
    related_finding_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence = round(max(0.0, min(1.0, float(self.confidence))), 2)
        if not self.severity:
            self.severity = severity_for(self.confidence)
        if not self.finding_id:
            identity = "\x1f".join((
                self.detector_version, self.rule_id, self.server, self.tool,
                self.source, self.location, self.evidence[:200],
            ))
            self.finding_id = sha256(identity.encode("utf-8", "replace")).hexdigest()[:24]
        if not self.category:
            self.category = finding_category(self.rule_id, self.tier)
        if not self.impact or not self.remediation:
            inferred_impact, inferred_remediation = finding_guidance(self.rule_id, self.tier)
            if not self.impact:
                self.impact = inferred_impact
            if not self.remediation:
                self.remediation = inferred_remediation

    def rescore(self, confidence: float) -> None:
        self.confidence = round(max(0.0, min(1.0, confidence)), 2)
        self.severity = severity_for(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_tool_raw(raw: Any) -> str | None:
    """Validate untrusted tool metadata before coercion or scanning."""
    if not isinstance(raw, dict):
        return "tool definition must be an object"
    if not isinstance(raw.get("name"), str) or not raw["name"].strip():
        return "tool name must be a nonempty string"
    if "description" in raw and not isinstance(raw["description"], str):
        return "tool description must be a string"
    for key in ("inputSchema", "input_schema", "outputSchema", "output_schema"):
        if key in raw and not isinstance(raw[key], dict):
            return f"{key} must be an object"
    for key in ("annotations", "_meta"):
        if key in raw and not isinstance(raw[key], dict):
            return f"{key} must be an object"
    return None


@dataclass
class ToolDef:
    server: str
    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)
    source: str = ""
    output_schema: dict | None = None
    annotations: dict = field(default_factory=dict)
    meta: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_mcp(cls, server: str, raw: dict, source: str = "") -> "ToolDef":
        validation_error = validate_tool_raw(raw)
        if validation_error:
            raise ValueError(validation_error)
        known = {"name", "description", "inputSchema", "input_schema", "outputSchema",
                 "output_schema", "annotations", "_meta"}
        return cls(
            server=server,
            name=str(raw.get("name", "")),
            description=str(raw.get("description", "") or ""),
            input_schema=raw.get("inputSchema") or raw.get("input_schema") or {},
            source=source,
            output_schema=raw.get("outputSchema") or raw.get("output_schema"),
            annotations=raw.get("annotations") if isinstance(raw.get("annotations"), dict) else {},
            meta=raw.get("_meta") if isinstance(raw.get("_meta"), dict) else {},
            extra={k: v for k, v in raw.items() if k not in known},
        )

    def to_dict(self) -> dict[str, Any]:
        result = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }
        if self.output_schema is not None:
            result["outputSchema"] = self.output_schema
        if self.annotations:
            result["annotations"] = self.annotations
        if self.meta:
            result["_meta"] = self.meta
        if self.extra:
            result.update(self.extra)
        return result


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
