"""Amass wrapper — deep passive enumeration with 60+ data sources."""

import json
from pathlib import Path

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class AmassWrapper:
    """Wrapper for OWASP Amass passive subdomain enumeration."""

    name: str = "amass"
    binary: str = "amass"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run amass passive enumeration against a domain."""
        output_path = get_temp_output_path("amass", "json")

        cmd = [
            "amass", "enum",
            "-passive",
            "-d", target,
            "-json", str(output_path),
        ]

        result = await run_tool(cmd, timeout=180)

        findings: list[ToolFinding] = []
        if output_path.exists():
            raw = output_path.read_text(errors="replace")
            findings = self.parse_output(raw, target=target)
            try:
                output_path.unlink()
            except OSError:
                pass

        return findings

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse amass JSON output."""
        findings: list[ToolFinding] = []
        seen: set[str] = set()

        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                name = data.get("name", "").strip()
                if name and name not in seen:
                    seen.add(name)
                    extra: dict = {"type": "subdomain"}
                    if "addresses" in data:
                        extra["addresses"] = data["addresses"]
                    if "asn" in data:
                        extra["asn"] = data["asn"]
                    if "cidr" in data:
                        extra["cidr"] = data["cidr"]
                    if "sources" in data:
                        extra["sources"] = data["sources"]

                    findings.append(ToolFinding(
                        title=f"Subdomain: {name}",
                        severity="info",
                        host=name,
                        tool_name=self.name,
                        evidence=name,
                        extra=extra,
                    ))
            except json.JSONDecodeError:
                continue

        return findings

    @staticmethod
    def is_installed() -> bool:
        """Check if amass is installed."""
        return check_binary("amass")
