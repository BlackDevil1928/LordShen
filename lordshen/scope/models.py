"""Scope data models — Pydantic v2 model for bug bounty program scope."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class ProgramScope(BaseModel):
    """Complete bug bounty program scope definition."""

    program_name: str = ""
    platform: str = "custom"  # hackerone, bugcrowd, intigriti, custom
    program_url: str = ""
    bounty: dict[str, int] = Field(default_factory=dict)
    in_scope_domains: list[str] = Field(default_factory=list)
    in_scope_ips: list[str] = Field(default_factory=list)
    in_scope_types: list[str] = Field(default_factory=list)
    oos_domains: list[str] = Field(default_factory=list)
    oos_vuln_classes: list[str] = Field(default_factory=list)
    oos_methods: list[str] = Field(default_factory=list)
    priority_vulns: list[str] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)
    auth_methods: list[str] = Field(default_factory=list)
    waf: str = ""
    environment: str = "production"
    rate_limit_rps: int = 10
    special_notes: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    model_config = {"extra": "allow"}

    def to_dict(self) -> dict[str, Any]:
        """Serialize scope to dictionary."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProgramScope":
        """Create scope from dictionary."""
        return cls(**data)

    @classmethod
    def from_json_file(cls, path: str) -> "ProgramScope":
        """Load scope from a JSON file."""
        import json
        from pathlib import Path
        raw = Path(path).read_text(encoding="utf-8")
        return cls(**json.loads(raw))

    def summary(self) -> str:
        """Return a brief text summary of this scope."""
        parts = [f"Program: {self.program_name} ({self.platform})"]
        parts.append(f"In-scope domains: {len(self.in_scope_domains)}")
        parts.append(f"In-scope IPs: {len(self.in_scope_ips)}")
        parts.append(f"OOS domains: {len(self.oos_domains)}")
        parts.append(f"OOS vuln classes: {len(self.oos_vuln_classes)}")
        if self.waf:
            parts.append(f"WAF: {self.waf}")
        if self.rate_limit_rps:
            parts.append(f"Rate limit: {self.rate_limit_rps} RPS")
        return " | ".join(parts)
