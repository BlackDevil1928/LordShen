"""Arjun wrapper — hidden HTTP parameter discovery."""

import json

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class ArjunWrapper:
    """Wrapper for Arjun HTTP parameter discovery tool."""

    name: str = "arjun"
    binary: str = "arjun"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run Arjun to discover hidden parameters."""
        output_path = get_temp_output_path("arjun", "json")

        cmd = [
            "arjun", "-u", target,
            "--stable",
            "-oJ", str(output_path),
            "-m", "GET,POST",
        ]

        result = await run_tool(cmd, timeout=300)

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
        """Parse Arjun JSON output."""
        findings: list[ToolFinding] = []
        target = kwargs.get("target", "")

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return findings

        if isinstance(data, dict):
            for url, params in data.items():
                if isinstance(params, list) and params:
                    findings.append(ToolFinding(
                        title=f"Hidden params on {url[:60]}: {', '.join(params[:5])}",
                        severity="info",
                        url=url,
                        tool_name=self.name,
                        evidence=f"Parameters found: {', '.join(params)}",
                        extra={
                            "type": "hidden_params",
                            "parameters": params,
                            "count": len(params),
                        },
                    ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("arjun")
