"""LordShen AI — Tool wrappers for security testing tools."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolFinding:
    """Standardized finding from any security tool."""

    title: str
    severity: str  # critical, high, medium, low, info
    host: str = ""
    url: str = ""
    evidence: str = ""
    cvss_score: float = 0.0
    description: str = ""
    tool_name: str = ""
    raw_output: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary for database storage."""
        return {
            "title": self.title,
            "severity": self.severity,
            "host": self.host,
            "url": self.url,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "tool_name": self.tool_name,
            "raw_output": self.raw_output[:5000],  # Truncate raw output
            "extra": self.extra,
        }


__all__ = ["ToolFinding"]
