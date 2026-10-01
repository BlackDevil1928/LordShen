"""ScoutSuite wrapper — cloud security posture assessment."""

import json
from pathlib import Path

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class ScoutSuiteWrapper:
    """Wrapper for ScoutSuite cloud security auditing."""

    name: str = "scoutsuite"
    binary: str = "scout"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run ScoutSuite cloud audit (requires cloud credentials in env)."""
        provider = kwargs.get("provider", "aws")
        report_dir = get_temp_output_path("scoutsuite", "dir").with_suffix("")

        cmd = f"scout {provider} --report-dir {report_dir} --no-browser --force"
        result = await run_tool(cmd, timeout=1800, shell=True)

        findings: list[ToolFinding] = []
        # Parse the ScoutSuite results JSON
        results_file = report_dir / "scoutsuite-results" / "scoutsuite_results.json"
        if results_file.exists():
            try:
                raw = results_file.read_text(errors="replace")
                findings = self.parse_output(raw, provider=provider)
            except Exception:
                pass

        return findings

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse ScoutSuite JSON results."""
        findings: list[ToolFinding] = []
        provider = kwargs.get("provider", "aws")

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return findings

        services = data.get("services", {})
        for service_name, service_data in services.items():
            if not isinstance(service_data, dict):
                continue
            flagged = service_data.get("findings", {})
            for finding_id, finding_data in flagged.items():
                if not isinstance(finding_data, dict):
                    continue

                level = finding_data.get("level", "info")
                severity = {"danger": "critical", "warning": "high"}.get(level, "medium")
                description = finding_data.get("description", finding_id)
                flagged_items = finding_data.get("flagged_items", 0)

                if flagged_items > 0:
                    findings.append(ToolFinding(
                        title=f"[{provider.upper()}] {service_name}: {description[:80]}",
                        severity=severity,
                        tool_name=self.name,
                        evidence=f"{flagged_items} resources flagged",
                        extra={
                            "type": "cloud_misconfig",
                            "provider": provider,
                            "service": service_name,
                            "finding_id": finding_id,
                            "flagged_items": flagged_items,
                        },
                    ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("scout")
