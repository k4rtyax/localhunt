"""
lokalHunt - Finding schema
JSON Schemas for Ollama's structured-output mode, plus the Finding record
every agent produces.
"""

from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Schema for a finder agent's response.
FINDINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": SEVERITIES},
                    "category": {"type": "string"},
                    "cwe": {"type": "string"},
                    "line": {"type": "integer"},
                    "evidence": {"type": "string"},
                    "impact": {"type": "string"},
                    "remediation": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": [
                    "title", "severity", "category", "line",
                    "evidence", "impact", "remediation", "confidence",
                ],
            },
        }
    },
    "required": ["findings"],
}

# Schema for a skeptic verifier's vote.
VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "real": {"type": "boolean"},
        "reason": {"type": "string"},
        "adjusted_severity": {"type": "string", "enum": SEVERITIES},
        "confidence": {"type": "number"},
    },
    "required": ["real", "reason", "adjusted_severity", "confidence"],
}

# Schema for the synthesizer's executive summary.
SUMMARY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "risk_level": {"type": "string", "enum": SEVERITIES},
        "top_priorities": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "risk_level", "top_priorities"],
}


@dataclass
class Finding:
    """One security finding, normalised across every agent."""

    title: str
    severity: str
    category: str
    line: int
    evidence: str
    impact: str
    remediation: str
    confidence: float
    file: str = ""
    cwe: str = ""
    agent: str = ""
    unverified_evidence: bool = False
    # Populated by the verify phase.
    votes: list[dict] = field(default_factory=list)
    verdict: str = "unverified"          # real | refuted | unverified
    verdict_reason: str = ""

    @classmethod
    def from_model(cls, raw: dict, *, agent: str, file: str, max_line: int) -> "Finding | None":
        """Build a Finding from raw model JSON, clamping anything out of range."""
        title = str(raw.get("title") or "").strip()
        if not title:
            return None

        severity = str(raw.get("severity") or "info").strip().lower()
        if severity not in SEVERITY_RANK:
            severity = "info"

        try:
            line = int(raw.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        line = max(0, min(line, max_line))

        try:
            confidence = float(raw.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(confidence, 1.0))

        return cls(
            title=title,
            severity=severity,
            category=str(raw.get("category") or agent).strip(),
            line=line,
            evidence=str(raw.get("evidence") or "").strip(),
            impact=str(raw.get("impact") or "").strip(),
            remediation=str(raw.get("remediation") or "").strip(),
            confidence=confidence,
            cwe=str(raw.get("cwe") or "").strip(),
            file=file,
            agent=agent,
        )

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, len(SEVERITIES))

    def dedupe_key(self) -> tuple:
        """Two agents reporting the same issue on the same line collapse into one."""
        from modules.textutil import normalize_snippet
        return (
            self.file,
            self.line,
            self.category.lower(),
            normalize_snippet(self.title)[:60],
        )

    def to_dict(self) -> dict:
        return asdict(self)
