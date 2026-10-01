"""wafw00f wrapper — Web Application Firewall detection."""

import json

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class Wafw00fWrapper:
    """Wrapper for wafw00f WAF identification tool."""

    name: str = "wafw00f"
    binary: str = "wafw00f"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Detect WAF protecting a target."""
        output_path = get_temp_output_path("wafw00f", "json")
        cmd = ["wafw00f", target, "-o", str(output_path), "-f", "json"]
        result = await run_tool(cmd, timeout=120)

        findings: list[ToolFinding] = []
        if output_path.exists():
            raw = output_path.read_text(errors="replace")
            findings = self.parse_output(raw, target=target)
            try:
                output_path.unlink()
            except OSError:
                pass
        elif result.stdout.strip():
            findings = self._parse_stdout(result.stdout, target)

        return findings

    def parse_output(self, raw: str, **kwargs) -> list[ToolFinding]:
        """Parse wafw00f JSON output."""
        findings: list[ToolFinding] = []
        target = kwargs.get("target", "")

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return findings

        if isinstance(data, list):
            for entry in data:
                url = entry.get("url", target)
                detected = entry.get("detected", False)
                firewall = entry.get("firewall", "None")
                manufacturer = entry.get("manufacturer", "")

                if detected:
                    findings.append(ToolFinding(
                        title=f"WAF Detected: {firewall} ({manufacturer})",
                        severity="info",
                        url=url,
                        tool_name=self.name,
                        evidence=f"WAF: {firewall} by {manufacturer}",
                        extra={
                            "type": "waf",
                            "waf_name": firewall,
                            "manufacturer": manufacturer,
                            "detected": True,
                        },
                    ))
                else:
                    findings.append(ToolFinding(
                        title="No WAF detected",
                        severity="info",
                        url=url,
                        tool_name=self.name,
                        evidence="No Web Application Firewall detected",
                        extra={"type": "waf", "detected": False},
                    ))

        return findings

    def _parse_stdout(self, stdout: str, target: str) -> list[ToolFinding]:
        """Fallback: parse wafw00f stdout text."""
        findings: list[ToolFinding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if "is behind" in line.lower():
                # Extract WAF name
                parts = line.split("is behind")
                waf_name = parts[1].strip().rstrip(".") if len(parts) > 1 else "Unknown"
                findings.append(ToolFinding(
                    title=f"WAF Detected: {waf_name}",
                    severity="info",
                    url=target,
                    tool_name=self.name,
                    evidence=line,
                    extra={"type": "waf", "waf_name": waf_name, "detected": True},
                ))
            elif "no waf" in line.lower():
                findings.append(ToolFinding(
                    title="No WAF detected",
                    severity="info",
                    url=target,
                    tool_name=self.name,
                    evidence=line,
                    extra={"type": "waf", "detected": False},
                ))
        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("wafw00f")
