"""CORS Scanner wrapper — CORS misconfiguration detection."""

import json
from pathlib import Path

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class CorsScannerWrapper:
    """Wrapper for CORS misconfiguration scanner."""

    name: str = "cors_scanner"
    binary: str = "cors_scanner"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Scan URLs for CORS misconfigurations."""
        output_path = get_temp_output_path("cors", "json")
        urls_file = kwargs.get("urls_file", "")

        if urls_file and Path(urls_file).exists():
            cmd = f"python3 -m cors_scanner -i {urls_file} -o {output_path}"
        else:
            # Create temp file with single URL
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write(target + "\n")
                temp_urls = f.name
            cmd = f"python3 -m cors_scanner -i {temp_urls} -o {output_path}"

        result = await run_tool(cmd, timeout=300, shell=True)

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
        """Parse CORS scanner JSON output."""
        findings: list[ToolFinding] = []
        target = kwargs.get("target", "")

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Try JSON lines
            for line in raw.strip().splitlines():
                try:
                    data = json.loads(line.strip())
                    if isinstance(data, dict):
                        finding = self._process_entry(data, target)
                        if finding:
                            findings.append(finding)
                except json.JSONDecodeError:
                    continue
            return findings

        if isinstance(data, list):
            for entry in data:
                finding = self._process_entry(entry, target)
                if finding:
                    findings.append(finding)
        elif isinstance(data, dict):
            finding = self._process_entry(data, target)
            if finding:
                findings.append(finding)

        return findings

    def _process_entry(self, entry: dict, target: str) -> ToolFinding | None:
        """Process a single CORS scan result."""
        url = entry.get("url", target)
        acao = entry.get("access-control-allow-origin", "")
        credentials = entry.get("access-control-allow-credentials", "")
        vulnerable = entry.get("vulnerable", False)
        vuln_type = entry.get("type", "")

        if not vulnerable and acao != "*":
            return None

        severity = "medium"
        if acao == "*" and credentials.lower() == "true":
            severity = "critical"
        elif acao == "null":
            severity = "high"
        elif acao == "*":
            severity = "high"

        return ToolFinding(
            title=f"CORS misconfiguration on {url[:60]}",
            severity=severity,
            url=url,
            tool_name=self.name,
            evidence=f"ACAO: {acao}, Credentials: {credentials}",
            description=f"CORS policy allows {acao} origin"
                        f"{' with credentials' if credentials.lower() == 'true' else ''}",
            extra={
                "type": "cors_misconfig",
                "acao": acao,
                "credentials": credentials,
                "vuln_type": vuln_type,
            },
        )

    @staticmethod
    def is_installed() -> bool:
        return check_binary("cors_scanner")
