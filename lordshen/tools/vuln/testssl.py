"""testssl.sh wrapper — SSL/TLS security audit."""

import json

from lordshen.tools import ToolFinding
from lordshen.tools.runner import run_tool, check_binary, get_temp_output_path


class TestsslWrapper:
    """Wrapper for testssl.sh SSL/TLS audit tool."""

    name: str = "testssl"
    binary: str = "testssl.sh"

    async def run(self, target: str, **kwargs) -> list[ToolFinding]:
        """Run testssl.sh against a target."""
        output_path = get_temp_output_path("testssl", "json")
        port = kwargs.get("port", 443)

        cmd = ["testssl.sh", "--jsonfile", str(output_path), f"{target}:{port}"]
        result = await run_tool(cmd, timeout=600)

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
        """Parse testssl.sh JSON output."""
        findings: list[ToolFinding] = []
        target = kwargs.get("target", "")

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return findings

        entries = data if isinstance(data, list) else data.get("scanResult", [{}])[0].get("serverDefaults", [])

        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue

            entry_id = entry.get("id", "")
            finding_text = entry.get("finding", "")
            severity_raw = entry.get("severity", "INFO").upper()

            # Map testssl severity
            severity = "info"
            if severity_raw in ("CRITICAL", "FATAL"):
                severity = "critical"
            elif severity_raw == "HIGH":
                severity = "high"
            elif severity_raw in ("MEDIUM", "WARN"):
                severity = "medium"
            elif severity_raw == "LOW":
                severity = "low"

            # Skip pure info entries
            if severity == "info" and entry_id not in (
                "BEAST", "POODLE", "HEARTBLEED", "CCS", "ROBOT", "SWEET32",
                "FREAK", "DROWN", "LOGJAM", "BREACH", "LUCKY13",
            ):
                continue

            # Upgrade known critical vulns
            if entry_id in ("HEARTBLEED", "DROWN", "CCS"):
                severity = "critical"
            elif entry_id in ("BEAST", "POODLE", "ROBOT", "FREAK"):
                severity = "high"

            if finding_text.lower() in ("not vulnerable", "no", "ok"):
                continue

            findings.append(ToolFinding(
                title=f"SSL/TLS: {entry_id} — {finding_text[:80]}",
                severity=severity,
                host=target,
                tool_name=self.name,
                evidence=finding_text,
                extra={
                    "type": "ssl_finding",
                    "test_id": entry_id,
                    "cve": entry.get("cve", ""),
                },
            ))

        return findings

    @staticmethod
    def is_installed() -> bool:
        return check_binary("testssl.sh") or check_binary("testssl")
