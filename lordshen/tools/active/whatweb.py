"""WhatWeb wrapper — technology fingerprinting."""

import json

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class WhatWebWrapper:
    """Wrapper for WhatWeb technology identification tool."""

    name: str = "whatweb"
    binary: str = "whatweb"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run WhatWeb to identify technologies on a target."""
        output_path = get_temp_output_path("whatweb", "json")
        aggression = kwargs.get("aggression", 3)

        cmd = ["whatweb", f"-a{aggression}", "--log-json", str(output_path), target]
        result = await run_tool(cmd, timeout=300)

        findings: list[ToolFinding] = []
        if output_path.exists():
            raw = output_path.read_text(errors="replace")
            findings = self.parse_output(raw)
            try:
                output_path.unlink()
            except OSError:
                pass

        return findings

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse WhatWeb JSON output."""
        findings: list[ToolFinding] = []

        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                target_url = data.get("target", "")
                plugins = data.get("plugins", {})
                status = data.get("http_status", 0)

                tech_list: list[str] = []
                for plugin_name, plugin_data in plugins.items():
                    if isinstance(plugin_data, dict):
                        version = plugin_data.get("version", [""])[0] if plugin_data.get("version") else ""
                        if version:
                            tech_list.append(f"{plugin_name} {version}")
                        else:
                            tech_list.append(plugin_name)

                if tech_list:
                    findings.append(ToolFinding(
                        title=f"Tech stack: {', '.join(tech_list[:5])}{'...' if len(tech_list) > 5 else ''}",
                        severity="info",
                        url=target_url,
                        tool_name=self.name,
                        evidence=f"Technologies: {', '.join(tech_list)}",
                        extra={
                            "type": "technology",
                            "technologies": tech_list,
                            "status_code": status,
                            "plugins": {k: v for k, v in list(plugins.items())[:20]},
                        },
                    ))
            except json.JSONDecodeError:
                continue

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("whatweb")
