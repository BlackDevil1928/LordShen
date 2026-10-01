"""Subfinder wrapper — passive subdomain enumeration with 50+ sources."""

import json
from pathlib import Path

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class SubfinderWrapper:
    """Wrapper for projectdiscovery/subfinder passive subdomain enumeration."""

    name: str = "subfinder"
    binary: str = "subfinder"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run subfinder against a domain.

        Args:
            target: Domain to enumerate subdomains for.

        Returns:
            List of ToolFinding objects with discovered subdomains.
        """
        output_path = get_temp_output_path("subfinder", "json")

        cmd = [
            "subfinder",
            "-d", target,
            "-all",
            "-recursive",
            "-silent",
            "-oJ", str(output_path),
        ]

        result = await run_tool(cmd, timeout=600)

        findings: list[ToolFinding] = []

        # Parse JSON lines output file
        if output_path.exists():
            raw = output_path.read_text(errors="replace")
            findings = self.parse_output(raw, target=target)
            try:
                output_path.unlink()
            except OSError:
                pass
        elif result.stdout.strip():
            # Fallback: parse stdout (plain text, one subdomain per line)
            for line in result.stdout.strip().splitlines():
                subdomain = line.strip()
                if subdomain and "." in subdomain:
                    findings.append(ToolFinding(
                        title=f"Subdomain: {subdomain}",
                        severity="info",
                        host=subdomain,
                        tool_name=self.name,
                        evidence=subdomain,
                        extra={"type": "subdomain"},
                    ))

        return findings

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse subfinder JSON lines output.

        Args:
            raw: Raw JSON lines content from subfinder.

        Returns:
            List of ToolFinding objects.
        """
        findings: list[ToolFinding] = []
        seen_subs: set[str] = set()

        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "").strip()
                if host and host not in seen_subs:
                    seen_subs.add(host)
                    findings.append(ToolFinding(
                        title=f"Subdomain: {host}",
                        severity="info",
                        host=host,
                        tool_name=self.name,
                        evidence=host,
                        extra={
                            "type": "subdomain",
                            "source": data.get("source", ""),
                            "input": data.get("input", ""),
                        },
                    ))
            except json.JSONDecodeError:
                # Plain text fallback
                if "." in line and line not in seen_subs:
                    seen_subs.add(line)
                    findings.append(ToolFinding(
                        title=f"Subdomain: {line}",
                        severity="info",
                        host=line,
                        tool_name=self.name,
                        evidence=line,
                        extra={"type": "subdomain"},
                    ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        """Check if subfinder is installed."""
        return check_binary("subfinder")
