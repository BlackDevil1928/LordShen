"""Subjack wrapper — subdomain takeover detection."""

from pathlib import Path

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class SubjackWrapper:
    """Wrapper for subjack subdomain takeover checker."""

    name: str = "subjack"
    binary: str = "subjack"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Check subdomains for potential takeover.

        Args:
            target: Not directly used (needs subs_file).
            subs_file: Path to file with subdomains to check.
        """
        output_path = get_temp_output_path("subjack", "txt")
        subs_file = kwargs.get("subs_file", "")

        if not subs_file or not Path(subs_file).exists():
            return []

        # Use bundled or default fingerprints
        fingerprints = kwargs.get("fingerprints", "")
        cmd = [
            "subjack",
            "-w", subs_file,
            "-t", "100",
            "-ssl",
            "-o", str(output_path),
        ]
        if fingerprints and Path(fingerprints).exists():
            cmd.extend(["-c", fingerprints])

        result = await run_tool(cmd, timeout=300)

        raw = ""
        if output_path.exists():
            raw = output_path.read_text(errors="replace")
            try:
                output_path.unlink()
            except OSError:
                pass

        return self.parse_output(raw)

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse subjack text output."""
        findings: list[ToolFinding] = []

        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # subjack output format: [Vulnerable] subdomain - service
            subdomain = line
            service = "unknown"

            if " - " in line:
                parts = line.split(" - ", 1)
                subdomain = parts[0].replace("[Vulnerable]", "").strip()
                service = parts[1].strip()

            findings.append(ToolFinding(
                title=f"Subdomain Takeover: {subdomain} ({service})",
                severity="high",
                host=subdomain,
                tool_name=self.name,
                evidence=line,
                description=f"Subdomain {subdomain} may be vulnerable to takeover via {service}",
                extra={"type": "subdomain_takeover", "service": service},
            ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("subjack")
